import {
	INodeType,
	INodeTypeDescription,
	IExecuteFunctions,
	NodeConnectionType,
	INodeExecutionData,
	IDataObject,
} from 'n8n-workflow';
import { exec } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { parseStringPromise } from 'xml2js';

const NSE_SCRIPTS = [
	{ name: 'http-enum', description: 'Enumerate directories used by popular web apps.' },
	{ name: 'vuln', description: 'Scan for vulnerabilities using multiple scripts.' },
	{ name: 'ssl-heartbleed', description: 'Check for Heartbleed vulnerability.' },
	{ name: 'ftp-anon', description: 'Detect anonymous FTP access.' },
	{ name: 'dns-brute', description: 'Enumerate DNS records.' },
	{ name: 'smb-os-discovery', description: 'Detect SMB server information.' },
	{ name: 'http-title', description: 'Fetch titles from HTTP servers.' },
];

export class NmapExecutor implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Nmap Executor',
		name: 'nmapExecutor',
		icon: 'fa:network-wired',
		group: ['transform'],
		version: 5,
		description: 'Run Nmap scans with presets, NSE scripts, smart parsing, logging and resiliency mode.',
		defaults: { name: 'Nmap Executor', color: '#1976D2' },
		inputs: ['main' as NodeConnectionType],
		outputs: ['main' as NodeConnectionType],
		properties: [
			{
				displayName: 'Target (IP or Host)',
				name: 'target',
				type: 'string',
				default: 'scanme.nmap.org',
				placeholder: '192.168.1.1 or example.com',
				description: 'IP, hostname or subnet to scan',
			},
			{
				displayName: 'Scan Mode',
				name: 'scanMode',
				type: 'options',
				default: 'fast',
				options: [
					{ name: 'Quick Scan', value: 'fast', description: 'Fast and basic scan (-T4 -F)' },
					{ name: 'Full Scan', value: 'full', description: 'Full port scan (-T4 -p1-65535)' },
					{ name: 'Service & Version Detection', value: 'version', description: 'Detect service versions (-sV)' },
					{ name: 'OS Detection', value: 'os', description: 'Detect operating system (-O)' },
					{ name: 'NSE Scripts', value: 'nse', description: 'Run selected NSE scripts' },
					{ name: 'Custom Flags', value: 'custom', description: 'Enter flags manually' },
				],
				description: 'Choose the scan type or enter custom flags.',
			},
			{
				displayName: 'NSE Scripts',
				name: 'nseScripts',
				type: 'multiOptions',
				options: NSE_SCRIPTS.map(s => ({
					name: `${s.name} — ${s.description}`,
					value: s.name
				})),
				default: [],
				displayOptions: {
					show: {
						scanMode: ['nse'],
					},
				},
				description: 'Select NSE scripts to run (only available if Scan Mode is "NSE Scripts")',
			},
			{
				displayName: 'Custom Nmap Flags',
				name: 'flags',
				type: 'string',
				default: '',
				placeholder: '-A -Pn',
				description: 'Only used if Scan Mode is "Custom Flags"',
				displayOptions: {
					show: {
						scanMode: ['custom'],
					},
				},
			},
			{
				displayName: 'Output Format',
				name: 'outputFormat',
				type: 'options',
				default: 'text',
				options: [
					{ name: 'Text', value: 'text' },
					{ name: 'XML', value: 'xml' },
					{ name: 'Greppable', value: 'grep' }
				],
				description: 'How to format the Nmap output',
			},
			{
				displayName: 'Timeout (seconds)',
				name: 'timeout',
				type: 'number',
				default: 60,
				description: 'Max seconds to wait for Nmap result',
			},
			{
				displayName: 'Nmap Path (optional)',
				name: 'nmapPath',
				type: 'string',
				default: 'nmap',
				placeholder: 'nmap or full path (e.g. C:\\Nmap\\nmap.exe)',
				description: 'Set this if nmap is not in PATH',
			},
			{
				displayName: 'Enable Smart Result',
				name: 'smartResult',
				type: 'boolean',
				default: true,
				description: 'Parse output (XML) as JSON and provide an intelligent summary.',
			},
			{
				displayName: 'Save Scan to History',
				name: 'saveHistory',
				type: 'boolean',
				default: true,
				description: 'Save scan output and summary to a local JSON log file.',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const outputs: INodeExecutionData[] = [];
		const historyPath = path.resolve(process.cwd(), 'nmap-history.jsonl');

		for (let i = 0; i < items.length; i++) {
			const target = this.getNodeParameter('target', i) as string;
			const scanMode = this.getNodeParameter('scanMode', i) as string;
			const smartResult = this.getNodeParameter('smartResult', i) as boolean;
			const saveHistory = this.getNodeParameter('saveHistory', i) as boolean;
			const outputFormat = this.getNodeParameter('outputFormat', i) as string;
			const timeout = Number(this.getNodeParameter('timeout', i)) || 60;
			const nmapPath = this.getNodeParameter('nmapPath', i) as string || 'nmap';

			let flags = '';
			if (scanMode === 'fast') flags = '-T4 -F';
			else if (scanMode === 'full') flags = '-T4 -p1-65535';
			else if (scanMode === 'version') flags = '-sV';
			else if (scanMode === 'os') flags = '-O';
			else if (scanMode === 'custom') flags = this.getNodeParameter('flags', i) as string;
			else if (scanMode === 'nse') {
				const nseScripts = this.getNodeParameter('nseScripts', i) as string[];
				flags = nseScripts.length ? `--script ${nseScripts.join(',')}` : '';
			}

			let formatFlag = '';
			if (outputFormat === 'xml') formatFlag = '-oX -';
			else if (outputFormat === 'grep') formatFlag = '-oG -';

			let resiliencyTried = false;
			let scanResult: IDataObject;
			let cmd = `"${nmapPath}" ${flags} ${formatFlag} "${target}"`;

			// Function to actually run nmap
			const runNmap = (cmdToRun: string): Promise<IDataObject> => {
				return new Promise<IDataObject>((resolve, reject) => {
					exec(cmdToRun, { timeout: timeout * 1000 }, (error, stdout, stderr) => {
						if (error) {
							reject({
								error: true,
								message: 'Nmap execution failed',
								details: stderr || error.message,
								cmd: cmdToRun,
								stdout,
								stderr,
							});
						} else {
							resolve({
								error: false,
								target,
								cmd: cmdToRun,
								output: stdout,
								format: outputFormat,
								flags,
							});
						}
					});
				});
			};

			try {
				scanResult = await runNmap(cmd);
			} catch (err: any) {
				// Detect host down / unreachable
				const downMsg =
					(err.details && typeof err.details === 'string' && (
						err.details.includes('0 hosts up') ||
						err.details.includes('Failed to resolve') ||
						err.details.match(/host.*down/i)
					));
				const alreadyPn = flags.includes('-Pn');
				if (downMsg && !alreadyPn) {
					resiliencyTried = true;
					// Reintentar con -Pn
					const resilientFlags = `${flags} -Pn`;
					const resilientCmd = `"${nmapPath}" ${resilientFlags} ${formatFlag} "${target}"`;
					try {
						scanResult = await runNmap(resilientCmd);
						scanResult.resiliency = {
							triggered: true,
							msg: 'First scan failed, retried with -Pn.',
							firstError: err,
						};
					} catch (err2: any) {
						// Falla incluso con -Pn
						scanResult = {
							...(typeof err2 === 'object' ? err2 : {}),
							resiliency: {
								triggered: true,
								msg: 'Scan failed even after retrying with -Pn.',
								firstError: err,
							}
						};
					}
				} else {
					// Otro error, no retry
					scanResult = typeof err === 'object' ? err : { error: true, message: String(err) };
				}
			}

			let parsed: any = null;
			let summary: any = null;
			if (
				smartResult &&
				!scanResult.error &&
				outputFormat === 'xml' &&
				typeof scanResult.output === 'string'
			) {
				try {
					parsed = await parseStringPromise(scanResult.output, { explicitArray: false });
					summary = makeSummary(parsed);
				} catch (e) {
					parsed = null;
					summary = { error: true, details: String(e) };
				}
			}

			// Save scan to local history log
			if (saveHistory) {
				const historyObj = {
					timestamp: new Date().toISOString(),
					target,
					flags,
					format: outputFormat,
					summary,
					...(scanResult.error ? { error: scanResult } : {}),
					...(scanResult.resiliency ? { resiliency: scanResult.resiliency } : {})
				};
				fs.appendFileSync(historyPath, JSON.stringify(historyObj) + '\n', 'utf8');
			}

			outputs.push({
				json: {
					...scanResult,
					...(smartResult && parsed ? { parsed } : {}),
					...(smartResult && summary ? { summary } : {}),
				},
			});
		}
		return [outputs];
	}
}

// --------- Helpers --------- //

function makeSummary(parsed: any): any {
	try {
		const host = parsed.nmaprun.host;
		const status = host.status?.$.state || 'unknown';
		const address = host.address?.$.addr || 'unknown';
		const ports = host.ports?.port;
		let openPorts: any[] = [];
		if (Array.isArray(ports)) {
			openPorts = ports.filter((p: any) => p.state.$.state === 'open');
		} else if (ports && ports.state?.$.state === 'open') {
			openPorts = [ports];
		}
		const portList = openPorts.map((p: any) => ({
			port: p.$.portid,
			service: p.service?.$.name || '',
			product: p.service?.$.product || '',
			version: p.service?.$.version || '',
			extra: p.service?.$.extrainfo || ''
		}));
		const nseResults = [];
		if (openPorts.length) {
			for (const p of openPorts) {
				if (p.script) {
					const scripts = Array.isArray(p.script) ? p.script : [p.script];
					for (const s of scripts) {
						nseResults.push({
							port: p.$.portid,
							script: s.$.id,
							output: s.$.output
						});
					}
				}
			}
		}
		return {
			address,
			status,
			openPorts: portList,
			totalOpen: openPorts.length,
			vulns: nseResults,
		};
	} catch (e) {
		return { error: true, details: String(e) };
	}
}

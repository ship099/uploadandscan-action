const util = require('util');
const { exec, execFileSync, spawn } = require('child_process');
const execPromise = util.promisify(exec);
const core = require('@actions/core');

const javaWrapperDownloadUrl 
  = 'https://repo1.maven.org/maven2/com/veracode/vosp/api/wrappers/vosp-api-wrappers-java'

async function downloadJar ()  {
  // get the latest version of the Veracode Java wrapper
  let latestVersion = '26.3.19.0'
  const runnerOS = process.env.RUNNER_OS;
  const curlCommand = `curl ${javaWrapperDownloadUrl}/maven-metadata.xml`;
  try {
    const { stdout } = await execPromise(curlCommand);
    // const lines = stdout.trim().split('\n');
    // const regex = /<latest>([\d.]+)<\/latest>/;
    // latestVersion = lines.find(line => regex.test(line)).match(regex)[1];
  } catch (error) {
    core.info(`Error executing curl command: ${error.message}`);
  }
  core.info(`Latest version of Veracode Java wrapper: ${latestVersion}`);

  // download the Veracode Java wrapper
  if(runnerOS == 'Windows'){
    const outFileName = `vosp-api-wrappers-java-${latestVersion}.jar`
    const jarUrl = `${javaWrapperDownloadUrl}/${latestVersion}/vosp-api-wrappers-java-${latestVersion}.jar`
    const powershellCommand = `powershell.exe Invoke-WebRequest -Uri "${jarUrl}" -OutFile "${outFileName}"`
    try {
      await execPromise(powershellCommand);
    } catch (error) {
      core.info(`Error executing powershell command: ${error.message}`);
    }

  }else{
    const wgetCommand = `wget ${javaWrapperDownloadUrl}/${latestVersion}/vosp-api-wrappers-java-${latestVersion}.jar`;
    try {
      await execPromise(wgetCommand);
    } catch (error) {
      core.info(`Error executing wget command: ${error.message}`);
    }
  }
  core.info(`Veracode Java wrapper downloaded: vosp-api-wrappers-java-${latestVersion}.jar`);
  return `vosp-api-wrappers-java-${latestVersion}.jar`;
}

async function runCommand (command, args = []){
  return new Promise((resolve, reject) => {
    const child = spawn(command, args);
    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (data) => {
      const output = data.toString();
      stdout += output;
      core.info(output.trimEnd());
    });

    child.stderr.on('data', (data) => {
      const output = data.toString();
      stderr += output;
      core.warning(output.trimEnd());
    });

    child.on('close', (code) => {
      if (code === 0) {
        core.info(`Command executed successfully (exit code: ${code})`);
        resolve(stdout);
      } else {
        core.warning(`Command execution completed with exit code: ${code}`);
        resolve(stdout);
      }
    });

    child.on('error', (error) => {
      core.error(`Failed to execute command: ${error.message}`);
      reject(error);
    });
  });
}

module.exports = {
  downloadJar,
  runCommand,
}
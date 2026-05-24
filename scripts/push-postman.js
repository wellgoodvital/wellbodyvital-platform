const fs = require('fs');
const path = require('path');

const apiKey = process.env.POSTMAN_API_KEY;
const workspaceId = process.env.POSTMAN_WORKSPACE_ID;
const root = path.resolve(__dirname, '..');
const collectionPath = path.join(root, 'postman', 'wellbodyvital-api.postman_collection.json');
const localEnvPath = path.join(root, 'postman', 'wellbodyvital-local.postman_environment.json');
const netlifyEnvPath = path.join(root, 'postman', 'wellbodyvital-netlify.postman_environment.json');
const postmanBaseUrl = 'https://api.getpostman.com';

if (!apiKey) {
  console.error('POSTMAN_API_KEY is missing. Export it in this shell before running this script.');
  process.exit(1);
}

async function postman(pathname, options = {}) {
  const response = await fetch(`${postmanBaseUrl}${pathname}`, {
    ...options,
    headers: {
      'X-API-Key': apiKey,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
  const text = await response.text();
  const body = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}: ${JSON.stringify(body)}`);
  }
  return body;
}

async function resolveWorkspace() {
  if (workspaceId) return workspaceId;
  const body = await postman('/workspaces');
  const workspaces = body.workspaces || [];
  if (workspaces.length === 1) return workspaces[0].id;
  console.error('POSTMAN_WORKSPACE_ID is required because this account has multiple or zero workspaces:');
  workspaces.forEach((workspace) => console.error(`- ${workspace.name}: ${workspace.id}`));
  process.exit(1);
}

async function createCollection(workspace) {
  const collection = JSON.parse(fs.readFileSync(collectionPath, 'utf8'));
  const body = await postman(`/collections?workspace=${workspace}`, {
    method: 'POST',
    body: JSON.stringify({ collection }),
  });
  return body.collection;
}

async function createEnvironment(workspace, filePath) {
  const environment = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const body = await postman(`/environments?workspace=${workspace}`, {
    method: 'POST',
    body: JSON.stringify({ environment }),
  });
  return body.environment;
}

async function main() {
  const workspace = await resolveWorkspace();
  const collection = await createCollection(workspace);
  const localEnv = await createEnvironment(workspace, localEnvPath);
  const netlifyEnv = await createEnvironment(workspace, netlifyEnvPath);

  console.log('Uploaded WellBodyVital Postman assets:');
  console.log(`- Collection: ${collection.name} (${collection.uid || collection.id})`);
  console.log(`- Environment: ${localEnv.name} (${localEnv.uid || localEnv.id})`);
  console.log(`- Environment: ${netlifyEnv.name} (${netlifyEnv.uid || netlifyEnv.id})`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});

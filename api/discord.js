import nacl from 'tweetnacl';

const {
  DISCORD_PUBLIC_KEY,
  DISCORD_ALLOWED_GUILD_ID,
  DISCORD_ALLOWED_CHANNEL_ID,
  GITHUB_TOKEN,
  GITHUB_OWNER,
  GITHUB_REPO,
  GITHUB_WORKFLOW_FILE,
  GITHUB_REF = 'main',
} = process.env;

function json(res, status, body) {
  res.status(status).setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(body));
}

function getOptionValue(interaction, optionName, fallback = null) {
  const options = interaction?.data?.options ?? [];
  const option = options.find((entry) => entry.name === optionName);
  return option?.value ?? fallback;
}

function verifyDiscordRequest(signature, timestamp, rawBody) {
  if (!signature || !timestamp || !DISCORD_PUBLIC_KEY) {
    return false;
  }

  return nacl.sign.detached.verify(
    Buffer.from(timestamp + rawBody),
    Buffer.from(signature, 'hex'),
    Buffer.from(DISCORD_PUBLIC_KEY, 'hex')
  );
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return json(res, 405, { error: 'Method Not Allowed' });
  }

  const signature = req.headers['x-signature-ed25519'];
  const timestamp = req.headers['x-signature-timestamp'];

  const rawBody = typeof req.body === 'string' ? req.body : JSON.stringify(req.body ?? {});

  const isValid = verifyDiscordRequest(signature, timestamp, rawBody);

  if (!isValid) {
    return json(res, 401, { error: 'invalid request signature' });
  }

  const interaction = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;

  if (interaction.type === 1) {
    return json(res, 200, { type: 1 });
  }
  if (interaction.type !== 2) {
    return json(res, 400, { error: 'unsupported interaction type' });
  }

  const permissions = BigInt(interaction?.member?.permissions || '0');

  const isAdmin = (permissions & 0x8n) === 0x8n;

  if (!isAdmin) {
    return json(res, 200, {
      type: 4,
      data: {
        content: ' Du hast keine Berechtigung, diesen Befehl auszuführen.',
        flags: 64,
      },
    });
  }

  if (DISCORD_ALLOWED_GUILD_ID && interaction.guild_id !== DISCORD_ALLOWED_GUILD_ID) {
    return json(res, 200, {
      type: 4,
      data: {
        content: 'Dieser Command ist hier nicht erlaubt',
        flags: 64,
      },
    });
  }
  if (DISCORD_ALLOWED_CHANNEL_ID && interaction.channel_id !== DISCORD_ALLOWED_CHANNEL_ID) {
    return json(res, 200, {
      type: 4,
      data: {
        content: 'Dieser Command ist nur im vorgesehen Channel erlaubt',
        flags: 64,
      },
    });
  }

  const commandName = interaction?.data?.name;
  if (commandName !== 'update') {
    return json(res, 200, {
      type: 4,
      data: {
        content: `unbekannter command ${commandName}`,
        flags: 64,
      },
    });
  }

  const environment =
    interaction?.data?.options?.find((o) => o.name === 'environment')?.value || 'staging';
  const requestedBy =
    interaction?.member?.user?.username || interaction?.user?.username || 'discord';

  const githubResponse = await fetch(
    `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/actions/workflows/${GITHUB_WORKFLOW_FILE}/dispatches`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${GITHUB_TOKEN}`,
        Accept: 'application/vnd.github+json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        ref: GITHUB_REF,
        inputs: {
          environment,
          requested_by: requestedBy,
        },
      }),
    }
  );

  if (!githubResponse.ok) {
    const errorText = await githubResponse.text();

    return json(res, 200, {
      type: 4,
      data: {
        content:
          `GitHub Action konnte nicht gestartet werden.\n` +
          `Status: ${githubResponse.status}\n` +
          `Antwort: ${errorText}`,
        flags: 64,
      },
    });
  }

  return json(res, 200, {
    type: 4,
    data: {
      content:
        `GitHub Action wurde gestartet.\n` +
        `Repo: ${GITHUB_OWNER}/${GITHUB_REPO}\n` +
        `Workflow: ${GITHUB_WORKFLOW_FILE}\n` +
        `Environment: ${environment}`,
      flags: 64,
    },
  });
}

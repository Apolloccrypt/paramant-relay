# Contributing to PARAMANT

## Ways to contribute

- Report security vulnerabilities: privacy@paramant.app
- Report bugs: [GitHub Issues](https://github.com/Apolloccrypt/paramant-relay/issues)
- Submit pull requests for fixes and improvements
- Test self-hosting on different platforms

## Development setup

```bash
git clone https://github.com/Apolloccrypt/paramant-relay
cd paramant-relay
cp .env.example .env
echo "ADMIN_TOKEN=$(openssl rand -hex 32)" >> .env
docker compose up -d
```

## Pull request guidelines

- One fix per PR
- Include test if applicable
- Update CHANGELOG.md under Unreleased section
- English only in code and comments

## Security

Do not open a public issue for security vulnerabilities.
Email privacy@paramant.app with responsible disclosure.

See [SECURITY.md](SECURITY.md) for full security policy.

## Hall of fame

Security researchers and contributors are listed in [SECURITY.md](SECURITY.md).

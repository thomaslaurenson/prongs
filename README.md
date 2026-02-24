# prongs

Fast, custom security scanner

## Requirements

- Python >=3.9

## Installation

### Option 1: Development setup using uv

- Requirements:
  - git
  - [uv](https://github.com/astral-sh/uv)

```bash
# Clone repo
git clone https://github.com/UoA-eResearch/prongs.git
cd prongs

# Install dependencies (including dev tools)
uv sync --all-extras

# Run
uv run prongs --help
```

### Option 2: Container

Pull the pre-built image from GitHub Container Registry:

```bash
docker pull ghcr.io/uoa-eresearch/prongs:latest
```

Or build locally:

```bash
docker build -f app/Dockerfile -t prongs .
```

## Usage

### CLI Examples

- Execute password SSH check against two target networks:

```bash
prongs -s password-ssh -t 192.168.0.0/32,192.168.88.0/32
```

- Execute all scanners against target networks specified in a file:

```bash
echo -e "192.168.0.0/32\n192.168.88.0/32" > targets.txt
prongs -s password-ssh -f targets.txt
```

- Execute password SSH scanner using environment variables:

```bash
TARGET_CIDRS=192.168.0.0/32,192.168.88.0/24 prongs -s password-ssh -e
```

### Docker Examples

- Run with all scanners and pull GHCR image:

```bash
docker run -e TARGET_CIDRS=192.168.0.0/32,192.168.88.0/24 ghcr.io/uoa-eresearch/prongs:latest
```

- Run with one scanner, using local image:

```bash
docker run -e TARGET_CIDRS=192.168.0.0/32,192.168.88.0/24 prongs:latest -s password-ssh
```

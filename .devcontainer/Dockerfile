# syntax=docker.io/docker/dockerfile:1.9

# see https://github.com/aws/aws-cli/tags
# see https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html#cliv2-linux-install
# renovate: datasource=github-tags depName=aws/aws-cli
ARG AWS_CLI_VERSION='2.17.26'

# see https://github.com/hashicorp/terraform/releases
# renovate: datasource=github-releases depName=hashicorp/terraform
ARG TERRAFORM_VERSION='1.9.4'

# see https://github.com/devcontainers/images/tree/main/src/base-debian/history
FROM mcr.microsoft.com/devcontainers/base:1.0.15-bookworm

RUN <<'EOF'
#!/usr/bin/bash
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y install --no-install-recommends \
    bash-completion \
    curl \
    python3-argcomplete \
    python3-pip \
    python3-venv \
    sudo \
    unzip
apt-get clean
rm -rf /var/lib/apt/lists/*
activate-global-python-argcomplete
python3 -m venv /opt/venv
EOF
ENV PATH="/opt/venv/bin:$PATH"

ARG AWS_CLI_VERSION
RUN <<'EOF'
#!/usr/bin/bash
set -euxo pipefail
aws_url="https://awscli.amazonaws.com/awscli-exe-linux-x86_64-${AWS_CLI_VERSION}.zip"
t="$(mktemp -q -d --suffix=.aws)"
wget -qO "$t/awscli.zip" "$aws_url"
unzip "$t/awscli.zip" -d "$t"
"$t/aws/install" \
    --bin-dir /usr/local/bin \
    --install-dir /usr/local/aws-cli \
    --update
rm -rf "$t"
# see https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-completion.html#cli-command-completion-linux
echo 'complete -C /usr/local/bin/aws_completer aws' \
    > /usr/share/bash-completion/completions/aws
EOF

ARG TERRAFORM_VERSION
ENV CHECKPOINT_DISABLE=1
RUN <<'EOF'
#!/usr/bin/bash
set -euxo pipefail
terraform_url="https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip"
t="$(mktemp -q -d --suffix=.terraform)"
wget -qO "$t/terraform.zip" "$terraform_url"
unzip "$t/terraform.zip" -d "$t"
install "$t/terraform" /usr/local/bin
rm -rf "$t"
terraform -install-autocomplete
EOF

RUN <<'EOF'
#!/usr/bin/bash
set -euxo pipefail
# ensure /etc/profile is called at the top of the file, when running in a
# login shell.
sed -i '0,/esac/s/esac/&\n\nsource \/etc\/profile/' /home/vscode/.bashrc
EOF
COPY inputrc /etc/inputrc
COPY login.sh /etc/profile.d/login.sh

COPY requirements.txt /tmp/pip-tmp/requirements.txt
RUN <<'EOF'
#!/usr/bin/bash
set -euxo pipefail
python -m pip \
    --disable-pip-version-check \
    --no-cache-dir \
    install \
    -r /tmp/pip-tmp/requirements.txt
rm -rf /tmp/pip-tmp
EOF

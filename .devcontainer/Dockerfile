FROM fedora:latest

# Update and install packages
RUN dnf -y makecache && \
    dnf -y install \
        axel \
        zsh \
        git \
        wget \
        ripgrep \
        unzip \
        openssh-server \
        neovim \
        rust-analyzer \
        clang \
        gcc \
        sudo \
        java-latest-openjdk-devel && \
    dnf clean all && \
    rm -rf /var/cache/dnf

# Create user 'dev' with home dir and zsh as default shell
RUN useradd -m -s /bin/zsh dev && \
    echo 'dev ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Switch to the new user
USER dev
WORKDIR /home/dev

# Install Rust non-interactively
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

# Add Cargo bin to PATH (for future RUN instructions)
ENV PATH="/home/dev/.cargo/bin:${PATH}"

# Set default shell
SHELL ["/bin/zsh", "-c"]

## Add ohmyzsh
RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended

## omz extensions, 1) fzf-tab
RUN git clone https://github.com/Aloxaf/fzf-tab ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/fzf-tab

## Use custom zsh file
RUN curl "https://raw.githubusercontent.com/FG-rps/test_repo/refs/heads/main/zshrc" > /home/dev/.zshrc

## Nvim stuff
RUN mkdir -p ~/.local/share/fonts
RUN curl "https://raw.githubusercontent.com/FG-rps/test_repo/refs/heads/main/CaskaydiaCoveNerdFont-Regular.ttf" > ~/.local/share/fonts/CaskaydiaCoveNerdFont-Regular.ttf
RUN git clone https://github.com/LazyVim/starter ~/.config/nvim
RUN rm ~/.config/nvim/init.lua
RUN curl "https://raw.githubusercontent.com/FG-rps/test_repo/refs/heads/main/init.lua" > ~/.config/nvim/init.lua

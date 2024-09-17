# Note: You can use any Debian/Ubuntu based image you want. 
FROM mcr.microsoft.com/devcontainers/anaconda:1-3
ARG WORKSPACE_FOLDER
ARG USERNAME

# Setup some tools and update
RUN \
    # Create workspace directory
    mkdir -p $WORKSPACE_FOLDER \
    && chown $USERNAME:$USERNAME $WORKSPACE_FOLDER

# Use the user created
USER $USERNAME

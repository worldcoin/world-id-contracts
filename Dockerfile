FROM ghcr.io/foundry-rs/foundry:latest

WORKDIR /world-id

COPY . .

# Fetch libs
RUN forge install

# Build the project
RUN forge build

# RUN ls script; exit 1
RUN ./script/generate_anvil_state.sh

ENTRYPOINT ["anvil", "--host", "0.0.0.0", "--load-state", "state.json"]
CMD []

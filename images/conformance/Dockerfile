# The official MCP conformance suite, pinned, in a container Probe runs inside the sandbox
# network against HTTP targets (docs/plan: section 17). Two versions side by side because the
# legacy and modern protocol eras have different suites.
FROM node:22-slim

RUN npm install -g --prefix /opt/c116 @modelcontextprotocol/conformance@0.1.16 \
 && npm install -g --prefix /opt/c020a11 @modelcontextprotocol/conformance@0.2.0-alpha.11 \
 && npm cache clean --force

COPY run.sh relay.mjs /opt/
RUN chmod 0755 /opt/run.sh

ENV HOME=/tmp npm_config_cache=/tmp/.npm
USER 10001:10001
ENTRYPOINT ["/opt/run.sh"]

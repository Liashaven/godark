FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@11.25.0 --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --prod --frozen-lockfile
COPY server ./server
COPY migrations ./migrations
COPY public ./public
EXPOSE 3000
CMD ["pnpm", "start"]

# Furix dashboard (Next.js 15). Build context = ./dashboard.
# NEXT_PUBLIC_API_URL is inlined at BUILD time. For the nginx-fronted deploy it
# is "" (empty) so the browser calls the SAME origin at /api (nginx routes it to
# the api service). For a standalone dev image, pass http://localhost:8000.
FROM node:20-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
ARG NEXT_PUBLIC_API_URL=""
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
# Bearer key the browser sends to the API (FUR-CMP-004). Inlined at build time.
ARG NEXT_PUBLIC_API_KEY="furix-dev-key"
ENV NEXT_PUBLIC_API_KEY=$NEXT_PUBLIC_API_KEY
RUN npm run build

FROM node:20-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/node_modules ./node_modules
EXPOSE 3000
CMD ["npm", "start"]

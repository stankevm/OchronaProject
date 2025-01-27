FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy prisma schema
COPY prisma ./prisma/

# Generate Prisma client
RUN npx prisma generate

# Copy rest of the application
COPY . .

# Expose port
EXPOSE 8080

# Wait for database then start application
CMD ["sh", "-c", "npx prisma migrate deploy && npm start"] 
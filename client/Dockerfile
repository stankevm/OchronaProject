FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy rest of the application
COPY . .

# Build the application
RUN npm run build

# Install serve to run the built application
RUN npm install -g serve

# Expose port
EXPOSE 5173

# Start the application
CMD ["npm", "run", "dev", "--", "--host"]

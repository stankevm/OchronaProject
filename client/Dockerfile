FROM node:18-alpine

WORKDIR /app

# kopiujemy package.json
COPY package*.json ./

# instalujemy zależności
RUN npm install

# kopiujemy resztę aplikacji
COPY . .

# budujemy aplikację
RUN npm run build

# instalujemy serve do uruchomienia aplikacji
RUN npm install -g serve

# eksponujemy port
EXPOSE 5173

# uruchamiamy aplikację
CMD ["npm", "run", "dev", "--", "--host"]

FROM node:18-alpine

WORKDIR /app

# kopiujemy package.json
COPY package*.json ./

# instalujemy zależności
RUN npm install

# kopiujemy prisma schema
COPY prisma ./prisma/

# generujemy prisma client
RUN npx prisma generate

# kopiujemy resztę aplikacji
COPY . .

# eksponujemy port
EXPOSE 8080

# czekamy na bazę danych a potem uruchamiamy aplikację
CMD ["sh", "-c", "npx prisma migrate deploy && npm start"] 
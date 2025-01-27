-- AlterTable
ALTER TABLE "Tweet" ADD COLUMN     "signature" TEXT,
ADD COLUMN     "verified" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "encryptedPrivateKey" TEXT,
ADD COLUMN     "publicKey" TEXT;

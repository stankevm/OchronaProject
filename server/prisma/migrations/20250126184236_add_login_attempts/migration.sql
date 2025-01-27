-- AlterTable
ALTER TABLE "User" ADD COLUMN     "lastAttempt" TIMESTAMP(3),
ADD COLUMN     "loginAttempts" INTEGER NOT NULL DEFAULT 0;

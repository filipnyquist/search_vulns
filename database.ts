import { SQLDatabase } from "encore.dev/storage/sqldb";

// Vulnerability database
export const vulnDb = new SQLDatabase("vulndb", {
  migrations: "./migrations/vuln"
});

// Product database  
export const productDb = new SQLDatabase("productdb", {
  migrations: "./migrations/product"
});
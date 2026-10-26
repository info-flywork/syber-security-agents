import { defineConfig } from "vitest/config";

// Veritabanı testleri aynı test veritabanını sıfırladığı için test dosyaları sırayla çalışır
export default defineConfig({ test: { fileParallelism: false } });

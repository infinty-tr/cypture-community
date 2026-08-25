# Cypture Değerlendirme (Eval) Harness'i

> **Amaç:** Ölçemediğin şeyi iyileştiremezsin. Bu harness, bilinen-zafiyetli hedeflere karşı
> Cypture'ı çalıştırır ve **bulma oranı (recall)** ile **kaba isabet (precision)** metriklerini
> üretir — böylece her model/prompt/araç değişikliğinin yeteneği nasıl etkilediğini SAYISAL
> görürsün ve regresyonları yakalarsın. Ürün koduna dokunmaz.

## Bileşenler
- `targets/` — bilinen-zafiyetli hedef(ler) için docker-compose (ör. OWASP Juice Shop).
- `expected/` — her hedef için BEKLENEN bulgu sınıfları (ground-truth).
- `run_eval.sh` — hedefi ayağa kaldırır, API üzerinden tarama başlatır, bekler, bulguları çeker, skorlar.
- `score.py` — bulunan bulguları beklenenlerle eşler; recall + precision + eksikler raporu.

## Çalıştırma
```bash
# 1) Cypture sunucusu çalışıyor olmalı (.env ile, docker runner) ve cypture-engine:latest hazır.
# 2) Hedefi ayağa kaldır + taramayı başlat + skorla:
cd eval
./run_eval.sh juice-shop            # varsayılan: strong model
CYP_EVAL_MODEL=frontier ./run_eval.sh juice-shop   # model tier'ını değiştir

# Sadece skorla (elindeki findings.json ile):
python3 score.py expected/juice-shop.json /tmp/eval-findings.json
```

## Metrikler
- **recall** = bulunan beklenen sınıf / toplam beklenen sınıf (yüksek = kapsam iyi).
- **precision (kaba)** = beklenen sınıfla eşleşen bulgu / toplam bulgu (düşük = gürültü/false-positive ↑).
- **verified_rate** = `verified:true` bulgu / toplam bulgu (doğrulama disiplini).
- **missing** = bulunamayan beklenen sınıflar (bir sonraki iyileştirmenin hedefi).

## Yorum
- Tek koşu kesin değildir (LLM stokastik) — **3-5 koşunun ortalamasını** al, varyansı not et.
- Değişiklik öncesi/sonrası aynı hedefte koş; recall ↑ ve precision sabit/↑ ise iyileşme gerçektir.
- Hedef havuzunu zamanla genişlet (DVWA, bWAPP, kendi lab uygulaman) — tek hedefe overfit etme.

> Not: Juice Shop tek konteynerdir ve internet egress gerektirir (imaj çekimi). Tarama, hedefe
> ağ erişimi olan bir Cypture docker runner gerektirir.

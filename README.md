# Melissa Framework

Rust tabanlı, geliştirme aşamasındaki ajan ve araç orkestrasyonu çatısı. Proje katkıya açıktır; tamamlanmış ürün veya üretim sürümü olarak sunulmaz.

Genel ajan/worker tanımları, skill paketleri, tipli sözleşmeler, kalıcılık, izin denetimi, araç bağlantıları, iş akışı ve hata toparlama kodları bulunur. Katalogdaki tanımlar, bütün ajanların aynı anda çalıştığı anlamına gelmez.

## Geliştirme

Rust ve Cargo gerekir. İşletim sistemi ve izole çalışma ortamına bağlı testlerin ek gereksinimleri vardır. Başlangıç kontrolleri:

```text
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked -p melissa-core-contracts -p melissa-local-store
cargo test --locked -p melissa-model-gateway --test reviewed_origin_policy
```

Katalogdaki backlog verileri şema ve sözleşme testleri için sentetik örneklerdir; proje görev listesi veya ilerleme raporu değildir.

## Katkı

Issue açabilir veya fork üzerinden PR gönderebilirsiniz. PR açıklamasında değişen davranışı, gerekçesini ve çalıştırılan kontrolleri yazın. Mümkün olduğunda tek konuya odaklanın; mevcut güvenlik ve hata durumu kontrollerini koruyun. Genel ajan/skill değişikliklerinde paket bütünlüğünü ve sürüm bağlarını doğrulayın.

Gizli anahtar, erişim bilgisi, kişisel yapılandırma, yerel veri tabanı, çalışma kaydı veya özel dosyaları commit etmeyin. Güvenlik açığı bildirirken çalışır erişim bilgilerini issue veya PR içine koymayın.

MIT lisansı: [LICENSE](LICENSE).

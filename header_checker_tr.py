"""
HTTP Security Header Checker
Bir URL'ye istek atar, response header'larını inceler ve
güvenlik açısından önemli header'ların eksik olup olmadığını raporlar.
"""

import requests


# Kontrol edeceğimiz güvenlik header'ları. Her header için iki bilgi tutuyoruz:
# "description" -> header ne işe yarar
# "risk" -> bu header eksik OLURSA, hangi senaryoda gerçek bir tehlike oluşturur
# İç içe dict kullanıyoruz: dış dict header ismine, iç dict ise o headera ait detaylara sahip.
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "XSS ve veri enjeksiyonu saldırılarına karşı hangi kaynaklardan içerik yüklenebileceğini sınırlar.",
        "risk": "Sitede bir XSS açığı varsa, saldırganın enjekte ettiği script hiçbir kısıtlama olmadan çalışabilir.",
    },
    "X-Frame-Options": {
        "description": "Sitenin başka bir sitede iframe içine gömülmesini engeller (clickjacking koruması).",
        "risk": "Saldırgan siteyi görünmez bir iframe içine gömüp kullanıcıyı fark ettirmeden gerçek sitede işlem yaptırabilir.",
    },
    "Strict-Transport-Security": {
        "description": "Tarayıcıyı siteye sadece HTTPS üzerinden bağlanmaya zorlar.",
        "risk": "Kullanıcı güvensiz bir ağdaysa (halka açık wifi vs.), http:// ile ilk bağlantıda araya girilip trafiği izlenebilir.",
    },
    "X-Content-Type-Options": {
        "description": "Tarayıcının dosya tipini 'tahmin etmesini' (MIME sniffing) engeller.",
        "risk": "Zararsız görünen bir dosya (örn. resim), tarayıcı tarafından çalıştırılabilir script gibi yorumlanabilir.",
    },
    "Referrer-Policy": {
        "description": "Kullanıcı başka bir siteye giderken ne kadar referrer bilgisi paylaşılacağını kontrol eder.",
        "risk": "URL'de hassas bilgi (örn. bir token) varsa, kullanıcı başka bir siteye tıkladığında bu bilgi o siteye sızabilir.",
    },
    "Permissions-Policy": {
        "description": "Kamera, mikrofon gibi tarayıcı özelliklerine hangi kaynakların erişebileceğini sınırlar.",
        "risk": "Sayfaya gömülü üçüncü parti bir içerik (reklam, iframe vs.) kullanıcının kamerasına/mikrofonuna izinsiz erişmeye çalışabilir.",
    },
}


def check_headers(url: str) -> dict:
    """
    Verilen URL'ye GET isteği atar ve güvenlik header'larının
    var olup olmadığını kontrol eder.

    Dönen değer: {"present": [...], "missing": [...]}
    """
    # timeout koymak önemli — karşı taraf yanıt vermezse script sonsuza kadar beklemesin.
    response = requests.get(url, timeout=10)

    # response.history: takip edilen tüm ara yönlendirmelerin listesi (302, 301 vs.)
    # Boşsa hiç yönlendirme olmamış demektir; response direkt istediğimiz sayfaya gitmiş.
    redirect_chain = []
    for step in response.history:
        redirect_chain.append((step.status_code, step.url))

    # requests, header isimlerine büyük/küçük harf duyarsız erişime izin veriyor
    # (HTTP header isimleri case-insensitive olduğu için bu doğru davranış).
    present = []
    missing = []

    for header_name, info in SECURITY_HEADERS.items():
        if header_name in response.headers:
            present.append((header_name, response.headers[header_name]))
        else:
            # info artık {"description": ..., "risk": ...} şeklinde bir dict,
            # ikisini birlikte missing listesine ekliyoruz.
            missing.append((header_name, info["description"], info["risk"]))

    return {
        "status_code": response.status_code,
        "final_url": response.url,       # yönlendirmelerden sonra gerçekten ulaşılan adres
        "redirect_chain": redirect_chain,
        "present": present,
        "missing": missing,
    }


def print_report(url: str, result: dict) -> None:
    """Sonuçları okunabilir şekilde ekrana basar."""
    print(f"\n=== {url} ===")
    print(f"Durum kodu: {result['status_code']}")

    if result["redirect_chain"]:
        print(f"\n🔀 Yönlendirme zinciri ({len(result['redirect_chain'])} adım):")
        for status, step_url in result["redirect_chain"]:
            print(f"   [{status}] {step_url}")
        print(f"   → Son adres: {result['final_url']}")
    else:
        print("\n🔀 Yönlendirme yok, direkt bu adrese ulaşıldı.")

    print()

    print(f"✅ Mevcut header'lar ({len(result['present'])}):")
    for name, value in result["present"]:
        print(f"   {name}: {value}")

    print(f"\n❌ Eksik header'lar ({len(result['missing'])}):")
    for name, description, risk in result["missing"]:
        print(f"   {name} — {description}")
        print(f"      ⚠️  Risk: {risk}")


if __name__ == "__main__":
    # Birden fazla URL almak için: kullanıcı virgülle ayırarak girebiliyor.
    # Örn: https://google.com, https://github.com, https://example.com
    raw_input_text = input(
        "Kontrol edilecek URL'ler (virgülle ayırarak birden fazla girebilirsin): "
    ).strip()

    # "a, b,c" gibi düzensiz boşluklu girişleri de temizlemek için
    # her parçayı .strip() ile ayrıca temizliyoruz.
    urls = [u.strip() for u in raw_input_text.split(",") if u.strip()]

    # Taramanın sonunda kısa bir özet çıkarmak için sonuçları biriktiriyoruz.
    summary = []

    for url in urls:
        try:
            result = check_headers(url)
            print_report(url, result)
            summary.append((url, len(result["missing"])))
        except requests.exceptions.RequestException as e:
            # Bir URL başarısız olursa diğerlerini taramaya devam ediyoruz —
            # tek bir hatalı adres yüzünden tüm tarama durmasın.
            print(f"\n=== {url} ===\nİstek başarısız oldu: {e}")
            summary.append((url, None))

    # Birden fazla site taradıysan, en sonda kısa bir kıyaslama tablosu göster.
    if len(urls) > 1:
        print("\n" + "=" * 40)
        print("ÖZET")
        print("=" * 40)
        for url, missing_count in summary:
            if missing_count is None:
                print(f"{url}: başarısız")
            else:
                print(f"{url}: {missing_count} header eksik")

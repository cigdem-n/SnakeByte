import time

RED = "\033[31m"
RESET = "\033[0m"

maskot_lines = [
    r"        /^\/^\ ",
    r"      _|__|  O|",
    r" \/     /~     \_/ \ ",
    r"  \____|__________/  \ ",
    r"         \_______     \ ",
    r"                 `\     \                 \ ",
    r"                   |     |                 \ ",
    r"                  /      /                  \ ",
    r"                 /     /                     \ ",
    r"               /      /                       \ \ ",
    r"              /     /                          \  \ ",
    r"            /     /             _----_          \   \ ",
    r"           /     /           _-~      ~-_        |   |",
    r"          (      (        _-~    _--_    ~-_    _/   |",
    r"           \      ~-____-~    _-~    ~-_    ~-_-~    /",
    r"             ~-_           _-~          ~-_      _-~",
    r"                ~--______-~               ~-___-~",
    r"",
]

def print_maskot():
    print(RED)
    for line in maskot_lines:
        print(line)
    print(RESET)

print("Yükleniyor...")
print_maskot()



import urllib.parse
import base64
import html
import re

# Encoder fonksiyonları

def url_encode(payload):
    return urllib.parse.quote(payload)

def base64_encode(payload):
    return base64.b64encode(payload.encode()).decode()

def html_entity_encode(payload):
    return html.escape(payload)

def unicode_encode(payload):
    return ''.join(f'\\u{ord(c):04x}' for c in payload)

def hex_encode(payload):
    return ''.join(f'\\x{ord(c):02x}' for c in payload)

def rot13_encode(payload):
    result = []
    for c in payload:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(c)
    return ''.join(result)

def double_url_encode(payload):
    return urllib.parse.quote(urllib.parse.quote(payload))

def mixed_encode(payload):
    url_encoded = urllib.parse.quote(payload)
    return base64.b64encode(url_encoded.encode()).decode()


# Decoder fonksiyonları

def url_decode(payload):
    return urllib.parse.unquote(payload)

def base64_decode(payload):
    try:
        return base64.b64decode(payload).decode()
    except Exception:
        return "[Invalid Base64]"

def html_entity_decode(payload):
    return html.unescape(payload)

def unicode_decode(payload):
    def replace_unicode(match):
        return chr(int(match.group(1), 16))
    return re.sub(r'\\u([0-9a-fA-F]{4})', replace_unicode, payload)

def hex_decode(payload):
    def replace_hex(match):
        return chr(int(match.group(1), 16))
    return re.sub(r'\\x([0-9a-fA-F]{2})', replace_hex, payload)

def rot13_decode(payload):
    return rot13_encode(payload)  # ROT13 encode ve decode aynıdır

def double_url_decode(payload):
    return urllib.parse.unquote(urllib.parse.unquote(payload))

def mixed_decode(payload):
    try:
        base64_decoded = base64.b64decode(payload).decode()
        return urllib.parse.unquote(base64_decoded)
    except Exception:
        return "[Invalid Mixed Encoding]"


# Otomatik decode tahmini

def guess_decode(payload):
    results = {}

    # URL Decode tahmini
    if '%' in payload:
        results['URL Decode'] = url_decode(payload)

    # Base64 tahmini
    base64_pattern = r'^[A-Za-z0-9+/=]+\Z'
    if re.match(base64_pattern, payload) and len(payload) % 4 == 0:
        results['Base64 Decode'] = base64_decode(payload)

    # HTML Entity tahmini
    if '&' in payload and ';' in payload:
        results['HTML Entity Decode'] = html_entity_decode(payload)

    # Unicode tahmini
    if '\\u' in payload:
        results['Unicode Decode'] = unicode_decode(payload)

    # Hex tahmini
    if '\\x' in payload:
        results['Hex Decode'] = hex_decode(payload)

    # ROT13 tahmini
    rot13_result = rot13_decode(payload)
    if sum(c.isalpha() for c in rot13_result) > len(payload) * 0.5:
        results['ROT13 Decode'] = rot13_result

    # Double URL Decode
    if payload.count('%') >= 2:
        results['Double URL Decode'] = double_url_decode(payload)

    # Mixed Decode deneme
    mixed_decoded = mixed_decode(payload)
    if mixed_decoded != "[Invalid Mixed Encoding]" and mixed_decoded != payload:
        results['Mixed Decode'] = mixed_decoded

    if not results:
        results['No decode method matched'] = payload

    return results


# Çoklu dil desteği

texts = {
    "tr": {
        "welcome": "🔥 WAF Bypass Encode/Decode Aracı",
        "select_mode": "👉 İşlem türü seç (E=Encode / D=Decode / 0=Çıkış): ",
        "select_encode": "👉 Hangi encode türünü kullanmak istersin?",
        "select_decode": "👉 Hangi decode türünü kullanmak istersin?",
        "menu_encode": """
1 - URL Encode
2 - Base64 Encode
3 - HTML Entity Encode
4 - Unicode Encode
5 - Hex Encode
6 - ROT13 Encode
7 - Double URL Encode
8 - Mixed Encode (URL + Base64)
9 - Tüm encode türlerini uygula
10 - Yeni payload gir
11 - Dosyadan payloadları oku ve encode et
12 - Dosyadan oku, tüm encode türlerini uygula ve kaydet
""",
        "menu_decode": """
1 - URL Decode
2 - Base64 Decode
3 - HTML Entity Decode
4 - Unicode Decode
5 - Hex Decode
6 - ROT13 Decode
7 - Double URL Decode
8 - Mixed Decode (Base64 + URL)
9 - Otomatik Decode (Tahmini)
""",
        "select_choice": "Seçimin (0-12): ",
        "select_decode_choice": "Decode seçimin (1-9): ",
        "input_payload": "💬 Payload girin: ",
        "input_file_path": "📂 Payload dosya yolu: ",
        "input_encode_type": "Hangi encode? (1-8): ",
        "input_decode_type": "Hangi decode? (1-9): ",
        "invalid_choice": "⛔ Geçersiz seçim!",
        "file_not_found": "⛔ Dosya bulunamadı!",
        "encoded_saved": "✅ Encode edilmiş payloadlar '{file}' dosyasına kaydedildi.",
        "all_encoded_saved": "✅ Tüm encode çıktıları '{file}' dosyasına kaydedildi.",
        "exit_message": "👋 Görüşürüz bebiş 💖",
        "invalid_choice_msg": "⛔ Geçersiz seçim yaptın bebiş.",
        "payload": "Payload",
        "encoded": "Encoded",
        "all_encodings": "--- 🔥 Tüm Encode Çıktıları ---",
        "decoded": "Decoded",
        "all_decodings": "--- 🔥 Tüm Decode Çıktıları ---"
    },
    "en": {
        "welcome": "🔥 WAF Bypass Encode/Decode Tool",
        "select_mode": "👉 Select mode (E=Encode / D=Decode / 0=Exit): ",
        "select_encode": "👉 Which encoding would you like to use?",
        "select_decode": "👉 Which decoding would you like to use?",
        "menu_encode": """
1 - URL Encode
2 - Base64 Encode
3 - HTML Entity Encode
4 - Unicode Encode
5 - Hex Encode
6 - ROT13 Encode
7 - Double URL Encode
8 - Mixed Encode (URL + Base64)
9 - Apply all encoding types
10 - Enter new payload
11 - Read payloads from file and encode
12 - Read from file, apply all encoding types and save
""",
        "menu_decode": """
1 - URL Decode
2 - Base64 Decode
3 - HTML Entity Decode
4 - Unicode Decode
5 - Hex Decode
6 - ROT13 Decode
7 - Double URL Decode
8 - Mixed Decode (Base64 + URL)
9 - Guess Decode (Automatic)
""",
        "select_choice": "Your choice (0-12): ",
        "select_decode_choice": "Decode choice (1-9): ",
        "input_payload": "💬 Enter payload: ",
        "input_file_path": "📂 Payload file path: ",
        "input_encode_type": "Which encode? (1-8): ",
        "input_decode_type": "Which decode? (1-9): ",
        "invalid_choice": "⛔ Invalid choice!",
        "file_not_found": "⛔ File not found!",
        "encoded_saved": "✅ Encoded payloads saved to '{file}'.",
        "all_encoded_saved": "✅ All encoded outputs saved to '{file}'.",
        "exit_message": "👋 See you later, babe 💖",
        "invalid_choice_msg": "⛔ Invalid choice, babe.",
        "payload": "Payload",
        "encoded": "Encoded",
        "all_encodings": "--- 🔥 All Encode Outputs ---",
        "decoded": "Decoded",
        "all_decodings": "--- 🔥 All Decode Outputs ---"
    }
}


def choose_language():
    lang = input("Select language / Dil seç (en/tr): ").lower()
    return "en" if lang == "en" else "tr"


def encode_and_save(input_file, encode_func, output_file, t):
    """Dosyadan oku, encode et ve kaydet"""
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            payloads = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(t["file_not_found"])
        return

    encoded_list = [encode_func(p) for p in payloads]

    with open(output_file, "w", encoding="utf-8") as f:
        for p, encoded in zip(payloads, encoded_list):
            print(f"{t['payload']}: {p}")
            print(f"{t['encoded']}: {encoded}\n")
            f.write(encoded + "\n")

    print(t["encoded_saved"].format(file=output_file))


def encode_all_and_save(input_file, output_file, t):
    """Dosyadan oku, tüm encode türlerini uygula, kaydet"""
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            payloads = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(t["file_not_found"])
        return

    with open(output_file, "w", encoding="utf-8") as f:
        for p in payloads:
            print(f"{t['payload']}: {p}")
            f.write(f"--- Payload: {p} ---\n")
            # Tüm encode fonksiyonları
            for key, (name, func) in encodings.items():
                encoded = func(p)
                print(f"{name}: {encoded}")
                f.write(f"{name}: {encoded}\n")
            print()
            f.write("\n")
    print(t["all_encoded_saved"].format(file=output_file))


encodings = {
    "1": ("URL Encode", url_encode),
    "2": ("Base64 Encode", base64_encode),
    "3": ("HTML Entity Encode", html_entity_encode),
    "4": ("Unicode Encode", unicode_encode),
    "5": ("Hex Encode", hex_encode),
    "6": ("ROT13 Encode", rot13_encode),
    "7": ("Double URL Encode", double_url_encode),
    "8": ("Mixed Encode", mixed_encode)
}

decodings = {
    "1": ("URL Decode", url_decode),
    "2": ("Base64 Decode", base64_decode),
    "3": ("HTML Entity Decode", html_entity_decode),
    "4": ("Unicode Decode", unicode_decode),
    "5": ("Hex Decode", hex_decode),
    "6": ("ROT13 Decode", rot13_decode),
    "7": ("Double URL Decode", double_url_decode),
    "8": ("Mixed Decode", mixed_decode),
    "9": ("Guess Decode (Automatic)", guess_decode)
}


def main():
    lang = choose_language()
    t = texts[lang]

    while True:
        print(t["welcome"])
        print("=" * 26)
        mode = input(t["select_mode"]).strip().upper()

        if mode == "E":
            print(t["menu_encode"])
            choice = input(t["select_choice"]).strip()
            if choice == "0":
                print(t["exit_message"])
                break
            elif choice in encodings:
                payload = input(t["input_payload"])
                name, func = encodings[choice]
                result = func(payload)
                print(f"\n🔐 {name} Result: {result}\n")

            elif choice == "9":
                payload = input(t["input_payload"])
                print(t["all_encodings"])
                for key, (name, func) in encodings.items():
                    result = func(payload)
                    print(f"{name}: {result}")
                print()

            elif choice == "10":
                # Yeni payload gir (zaten input alındı, devam)
                continue

            elif choice == "11":
                input_file = input(t["input_file_path"])
                output_file = "encoded_output.txt"
                print(f"Encoding payloads from file '{input_file}' and saving to '{output_file}'...")
                # Kullanıcı hangi encode seçti?
                print(t["menu_encode"])
                enc_choice = input(t["input_encode_type"]).strip()
                if enc_choice in encodings:
                    _, func = encodings[enc_choice]
                    encode_and_save(input_file, func, output_file, t)
                else:
                    print(t["invalid_choice_msg"])

            elif choice == "12":
                input_file = input(t["input_file_path"])
                output_file = "all_encoded_output.txt"
                encode_all_and_save(input_file, output_file, t)

            else:
                print(t["invalid_choice_msg"])

        elif mode == "D":
            print(t["menu_decode"])
            choice = input(t["select_decode_choice"]).strip()
            if choice == "0":
                print(t["exit_message"])
                break
            elif choice in decodings:
                payload = input(t["input_payload"])
                name, func = decodings[choice]
                result = func(payload)
                if isinstance(result, dict):
                    print(t["all_decodings"])
                    for method, val in result.items():
                        print(f"{method}: {val}")
                    print()
                else:
                    print(f"\n🔐 {name} Result: {result}\n")

            else:
                print(t["invalid_choice_msg"])

        elif mode == "0":
            print(t["exit_message"])
            break
        else:
            print(t["invalid_choice_msg"])


if __name__ == "__main__":
    main()

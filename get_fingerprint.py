import os
import subprocess
import re
from flask import Flask, request, render_template_string

app = Flask(__name__)
UPLOAD_FOLDER = '/tmp'

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>APK Info Extractor</title>
    <style>
        body { font-family: sans-serif; margin: 40px; background: #fafafa; color: #333; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .result-box { background: #f4f4f5; padding: 15px; border-radius: 6px; margin-top: 20px; }
        .label { font-weight: bold; color: #555; margin-bottom: 5px; }
        .value { font-family: monospace; font-size: 14px; word-break: break-all; background: #fff; padding: 8px; border: 1px solid #e4e4e7; border-radius: 4px; margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>APK 情報抽出ツール</h2>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="apk_file" accept=".apk" required>
            <button type="submit">アップロードして解析</button>
        </form>

        {% if error %}
            <div class="result-box" style="color: red;">{{ error }}</div>
        {% endif %}

        {% if package_name or sha256 %}
            <div class="result-box">
                {% if package_name %}
                    <div class="label">📦 パッケージ名:</div>
                    <div class="value">{{ package_name }}</div>
                {% endif %}
                
                {% if sha256 %}
                    <div class="label">🔑 SHA-256 フィンガープリント (コロン区切り):</div>
                    <div class="value">{{ sha256 }}</div>
                {% endif %}
            </div>
        {% endif %}
    </div>
</body>
</html>
"""

def convert_sha256(raw_sha256):
    upper_str = raw_sha256.upper()
    return ":".join(upper_str[i:i+2] for i in range(0, len(upper_str), 2))

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    package_name = None
    sha256 = None
    error = None

    if request.method == 'POST':
        file = request.files['apk_file']
        if file and file.filename.endswith('.apk'):
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)
            
            try:
                # 1. apksigner で SHA-256 を抽出
                cmd_signer = f"apksigner verify --print-certs {filepath}"
                output_signer = subprocess.check_output(cmd_signer, shell=True, text=True)
                sha_match = re.search(r"SHA-256 digest:\s*([a-fA-F0-9]{64})", output_signer)
                if sha_match:
                    sha256 = convert_sha256(sha_match.group(1))

                # 2. aapt で本当のパッケージ名を抽出 (AndroidManifest.xmlを解析)
                # ※apksignerと同じフォルダにあるのでそのまま「aapt」で呼べるはずですが、
                # もしエラーが出る場合はフルパス（例: /Users/ユーザー名/Library/Android/sdk/build-tools/34.0.0/aapt）にしてください。
                cmd_aapt = f"aapt dump badging {filepath}"
                output_aapt = subprocess.check_output(cmd_aapt, shell=True, text=True)
                
                # package: name='com.example.app' の形式から抽出
                pkg_match = re.search(r"package: name='([^']+)'", output_aapt)
                if pkg_match:
                    package_name = pkg_match.group(1)
                else:
                    package_name = "パッケージ名が検出できませんでした"

            except Exception as e:
                error = f"エラーが発生しました: {str(e)}"
            finally:
                if os.path.exists(filepath):
                    os.remove(filepath)
                    
    return render_template_string(HTML_TEMPLATE, package_name=package_name, sha256=sha256, error=error)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
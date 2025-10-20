# 💻WebTaskmgr

「たった一つのPHPファイルだけで動作する」がコンセプトのサーバー管理用の多機能タスクマネージャーです。

Web上でリソース管理からプロセス操作、ファイル編集まで全部が完結します。パスワード設定やIPアドレス制限にも対応しています。

## 🚀導入方法

リポジトリ内の `WebTaskmgr.php` をダウンロードしてFTPやscpでサーバーにアップロードするか、
サーバーの好きな場所に好きな名前のPHPファイルを作成して、`WebTaskmgr.php`の中身をそのままコピー・ペーストしてください。

そのままブラウザから当該ファイルにアクセスするだけで利用できます。
初期状態だとパスワードが未設定であり不正アクセスのリスクがありますので、「設定」のタブからパスワードを設定するか、アクセス元のIPアドレスを制限してください。

## 🖼️画面の例

<img width="1281" height="812" alt="スクリーンショット 2025-09-12 135632" src="https://github.com/user-attachments/assets/e2ff5272-f2f9-426f-9b03-fd9f69cab1b1" />
<img width="1289" height="704" alt="スクリーンショット 2025-09-12 135839" src="https://github.com/user-attachments/assets/ec8c1dcd-59c2-48ef-a19a-6f56f8b01b9d" />
<img width="1290" height="901" alt="スクリーンショット 2025-09-12 135738" src="https://github.com/user-attachments/assets/7774c093-a17b-4c4f-a51a-786e9108c34c" />
<img width="1508" height="846" alt="スクリーンショット 2025-09-12 135909" src="https://github.com/user-attachments/assets/7aff6073-29e0-4484-819a-ac9c05fdc316" />
<img width="1323" height="827" alt="image" src="https://github.com/user-attachments/assets/47643fec-f02a-45c4-87b6-73530dc524bd" />

## 🕵️機能

### 1) 全体概要

・システム仕様の表示

・CPU、メモリ、Load Average、GPUのリアルタイム監視（800ms間隔)

### 2) タスク管理

・プロセスを一覧表示

・好きな項目でソート可能

・プロセス操作(停止・再開・終了・強制終了)

### 3) ファイル管理

・ディレクトリ内のファイル一覧の閲覧

・ZIPファイルは内部にそのままあたかもディレクトリかのようにアクセス可能

・ファイルの閲覧・プレビュー

・Monaco Editorによるファイル編集 (読み取り専用モードあり)

・Hexダンプ表示

・ファイルのアップロード (分割アップロードに対応)

・URLからサーバー側ダウンロード

・ZIPファイルの圧縮/展開

・ショートカット作成機能

・AESによるファイル暗号化

#### 4) ターミナル

・tmuxによるフルカラーのターミナル制御

・tmuxのない環境でも自動でフォールバックして対応

・複数タブ機能

#### 5) 設定

・パスワード設定/削除

・IPアドレス制限

## 📝ライセンス

このプログラムは The MIT License の下で公開されています。

© 2025 ActiveTK.  
🔗 https://github.com/ActiveTK/gff/blob/master/LICENSE


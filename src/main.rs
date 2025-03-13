use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::RngCore;
use rand::rngs::OsRng;
use std::fs::File;
use std::io::{Read, Write};
use std::error::Error;
use eframe::egui;
use chrono::Local;

/// Типовий псевдонім для зручності
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

/// Функція для шифрування файлу.
/// Повертає список рядків логів, які описують процес.
fn encrypt_file(input_path: &str, output_path: &str, key: &[u8]) -> Result<Vec<String>, Box<dyn Error>> {
    let mut logs = Vec::new();

    // Лог про зчитування файлу
    logs.push(format!("Зчитано файл: {}", input_path));

    // Зчитування даних із вхідного файлу
    let mut input_file = File::open(input_path)?;
    let mut data = Vec::new();
    input_file.read_to_end(&mut data)?;

    // Генерація випадкового IV (ініціалізаційного вектора)
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    // Ініціалізація шифру AES-256-CBC
    let cipher = Aes256Cbc::new_from_slices(key, &iv)
        .map_err(|e| format!("Помилка ініціалізації шифру: {}", e))?;
    let ciphertext = cipher.encrypt_vec(&data);

    // Запис у вихідний файл: спочатку IV, потім зашифровані дані
    let mut output_file = File::create(output_path)?;
    output_file.write_all(&iv)?;
    output_file.write_all(&ciphertext)?;

    // Логи про результат
    logs.push(format!("Файл зашифровано та збережено: {}", output_path));
    logs.push("Шифрування пройшло успішно.".to_string());

    Ok(logs)
}

/// Функція для дешифрування файлу.
/// Повертає список рядків логів, які описують процес.
fn decrypt_file(input_path: &str, output_path: &str, key: &[u8]) -> Result<Vec<String>, Box<dyn Error>> {
    let mut logs = Vec::new();

    // Лог про зчитування файлу
    logs.push(format!("Зчитано файл: {}", input_path));

    // Зчитування даних із зашифрованого файлу
    let mut input_file = File::open(input_path)?;
    let mut data = Vec::new();
    input_file.read_to_end(&mut data)?;

    // Перевірка наявності мінімальної кількості байт (16 для IV)
    if data.len() < 16 {
        return Err("Дані файлу некоректні, недостатньо байтів для IV".into());
    }

    // Виділення IV та зашифрованих даних
    let iv = &data[..16];
    let ciphertext = &data[16..];

    // Ініціалізація дешифрувальника
    let cipher = Aes256Cbc::new_from_slices(key, iv)
        .map_err(|e| format!("Помилка ініціалізації дешифрувальника: {}", e))?;
    let decrypted_data = cipher.decrypt_vec(ciphertext)
        .map_err(|e| format!("Помилка дешифрування: {}", e))?;

    // Запис розшифрованих даних у вихідний файл
    let mut output_file = File::create(output_path)?;
    output_file.write_all(&decrypted_data)?;

    // Логи про результат
    logs.push(format!("Файл дешифровано та збережено: {}", output_path));
    logs.push("Дешифрування пройшло успішно.".to_string());

    Ok(logs)
}

/// Структура, що представляє стан додатку.
struct MyApp {
    input_path: String,
    output_path: String,
    key: String,
    logs: Vec<String>,
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            input_path: "input.txt".to_owned(),
            output_path: "encrypted.bin".to_owned(),
            // Ключ повинен містити рівно 32 байти.
            key: "an_example_very_very_secret_key!".to_owned(),
            logs: Vec::new(),
        }
    }
}

impl MyApp {
    /// Функція для додавання рядка логів з поточним часом.
    fn push_log(&mut self, level: &str, msg: &str) {
        let now = Local::now().format("%H:%M:%S");
        self.logs.push(format!("{} [{}] {}", now, level, msg));
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("File Encryptor / Decryptor");

            // Поле для введення шляху вхідного файлу
            ui.horizontal(|ui| {
                ui.label("Вхідний файл:");
                ui.text_edit_singleline(&mut self.input_path);
            });

            // Поле для введення шляху вихідного файлу
            ui.horizontal(|ui| {
                ui.label("Вихідний файл:");
                ui.text_edit_singleline(&mut self.output_path);
            });

            // Поле для введення ключа
            ui.horizontal(|ui| {
                ui.label("Ключ (32 байти):");
                ui.text_edit_singleline(&mut self.key);
            });

            // Кнопки "Шифрування" та "Дешифрування"
            ui.horizontal(|ui| {
                if ui.button("Шифрування").clicked() {
                    if self.key.len() != 32 {
                        self.push_log("ERROR", "Ключ повинен містити 32 байти для AES-256.");
                    } else {
                        match encrypt_file(&self.input_path, &self.output_path, self.key.as_bytes()) {
                            Ok(log_messages) => {
                                // Додаємо кожне повідомлення з encrypt_file
                                for msg in log_messages {
                                    self.push_log("INFO", &msg);
                                }
                            }
                            Err(e) => self.push_log("ERROR", &format!("Помилка шифрування: {}", e)),
                        }
                    }
                }
                if ui.button("Дешифрування").clicked() {
                    if self.key.len() != 32 {
                        self.push_log("ERROR", "Ключ повинен містити 32 байти для AES-256.");
                    } else {
                        match decrypt_file(&self.input_path, &self.output_path, self.key.as_bytes()) {
                            Ok(log_messages) => {
                                // Додаємо кожне повідомлення з decrypt_file
                                for msg in log_messages {
                                    self.push_log("INFO", &msg);
                                }
                            }
                            Err(e) => self.push_log("ERROR", &format!("Помилка дешифрування: {}", e)),
                        }
                    }
                }
            });

            // Третя кнопка "Зберегти логи у файл"
            if ui.button("Зберегти логи у файл").clicked() {
                match File::create("input.log") {
                    Ok(mut file) => {
                        use std::io::Write;
                        for log_line in &self.logs {
                            if let Err(e) = writeln!(file, "{}", log_line) {
                                self.push_log("ERROR", &format!("Не вдалося записати лог: {}", e));
                                break;
                            }
                        }
                        self.push_log("INFO", "Логи успішно збережено у input.log");
                    }
                    Err(e) => self.push_log("ERROR", &format!("Не вдалося створити файл логів: {}", e)),
                }
            }

            ui.separator();
            ui.label("Логи:");
            // Область з прокручуванням для відображення логів
            egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                for log in &self.logs {
                    ui.label(log);
                }
            });
        });
    }
}

fn main() {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "File Encryptor / Decryptor", 
        native_options,
        Box::new(|_cc| Box::new(MyApp::default())),
    );
}

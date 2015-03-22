#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <QString>
#include <QFileDialog>
#include <QMessageBox>
#include <QFile>

#include "ecrypt.h"
#include "ui_ecrypt.h"
#include "estream.h"

// Глобальные переменные
uint8_t key[32], iv[16];
int alg = 0;
int keylen, ivlen;
int block = 1000000;

ecrypt::ecrypt(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::ecrypt)
{
    ui->setupUi(this);

    // Отключаем кнопку "Развернуть"
    setWindowFlags(Qt::Window | Qt::WindowCloseButtonHint | Qt::WindowMinimizeButtonHint | Qt::CustomizeWindowHint);

    // Скрываем кнпки "Начать снова" и "Экспорт ключа и вектора"
    ui->pushButton_6->setVisible(false);
    ui->pushButton_7->setVisible(false);

    // Отрабатывает когда выбран алгоритм
    connect(ui->comboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(select_algorithm()));

    // Вызов слота при нажатии на кнопку
    connect(ui->pushButton_1, SIGNAL(clicked()), this, SLOT(set_mod_lineedit_1()));
    connect(ui->pushButton_2, SIGNAL(clicked()), this, SLOT(set_mod_lineedit_2()));
    connect(ui->pushButton_3, SIGNAL(clicked()), this, SLOT(get_input_file()));
    connect(ui->pushButton_4, SIGNAL(clicked()), this, SLOT(get_output_file()));
    connect(ui->pushButton_5, SIGNAL(clicked()), this, SLOT(base_func()));
    connect(ui->pushButton_6, SIGNAL(clicked()), this, SLOT(new_form()));
    connect(ui->pushButton_7, SIGNAL(clicked()), this, SLOT(export_ket_and_iv()));
}

ecrypt::~ecrypt()
{
    delete ui;
}

// Очистка формы.
void ecrypt::new_form()
{
    ui->pushButton_6->setVisible(false);
    ui->pushButton_7->setVisible(false);
    ui->pushButton_5->setVisible(true);

    // Очищаем все поля
    ui->lineEdit_1->clear();
    ui->lineEdit_2->clear();
    ui->lineEdit_3->clear();
    ui->lineEdit_4->clear();

    // Форма ввода пароля и вектора инициализации: Пароль
    ui->pushButton_1->setText("Скрыть");
    ui->pushButton_2->setText("Скрыть");
    ui->lineEdit_1->setEchoMode(QLineEdit::Password);
    ui->lineEdit_2->setEchoMode(QLineEdit::Password);
}

// Выбор алгоритма. На основании выбранного алгоритма ограничивается размер для ввода пароля и вектора.
void ecrypt::select_algorithm()
{
    alg = ui->comboBox->currentIndex();

    switch(alg) {
    case 0 : ui->label_6->setText("Salsa - криптографический алгортим!\nПобедитель проекта eSTREAM."\
                                  "\nТехнические характеристики:\nКлюч: 32 байта\nВектор: 8 байт");
             ui->lineEdit_1->setMaxLength(32);
             ui->lineEdit_2->setMaxLength(8);
             break;
    case 1 : ui->label_6->setText("Rabbit - криптографический алгортим!\nПобедитель проекта eSTREAM."\
                                  "\nТехнические характеристики:\nКлюч: 16 байт\nВектор: 8 байт");
             ui->lineEdit_1->setMaxLength(16);
             ui->lineEdit_2->setMaxLength(8);
             break;
    case 2 : ui->label_6->setText("HC128 - криптографический алгоритм!\nПобедитель проекта eSTREAM.\n"\
                                  "Технические характеристики:\nКлюч: 16 байт\nВектор: 16 байт");
             ui->lineEdit_1->setMaxLength(16);
             ui->lineEdit_2->setMaxLength(16);
             break;
    case 3 : ui->label_6->setText("Sosemanuk - криптографический алгоритм!\nПобедитель проекта eSTREAM.\n"\
                                  "Технические характеристики:\nКлюч: 32 байта\nВектор: 16 байт");
             ui->lineEdit_1->setMaxLength(32);
             ui->lineEdit_2->setMaxLength(16);
             break;
    case 4 : ui->label_6->setText("Grain - криптографический алгоритм!\nПобедитель проекта eSTREAM."\
                                  "\nТехнические характеристики:\nКлюч: 16 байт\nВектор: 12 байт");
             ui->lineEdit_1->setMaxLength(16);
             ui->lineEdit_2->setMaxLength(12);
             break;
    case 5 : ui->label_6->setText("Mickey - криптографический алгоритм!\nПобедитель проекта eSTREAM."\
                                  "\nТехнические характеристики:\nКлюч: 10 байт\nВектор: 10 байт");
             ui->lineEdit_1->setMaxLength(10);
             ui->lineEdit_2->setMaxLength(10);
             break;
    case 6 : ui->label_6->setText("Trivium - криптографический алгоритм!\nПобедитель проекта eSTREAM."\
                                  "\nТехнические характеристики:\nКлюч: 10 байт\nВектор: 10 байт");
             ui->lineEdit_1->setMaxLength(10);
             ui->lineEdit_2->setMaxLength(10);
             break;
    }
}

// Изменяем режим отображения для поля ввода пароля (точки или символы)
void ecrypt::set_mod_lineedit_1()
{
   if(ui->pushButton_1->text() == "Отобразить") {
        ui->lineEdit_1->setEchoMode(QLineEdit::Normal);
        ui->pushButton_1->setText("Скрыть");
   }
   else {
        ui->lineEdit_1->setEchoMode(QLineEdit::Password);
        ui->pushButton_1->setText("Отобразить");
   }
}

// Изменяем режим отображения для поля ввода вектора инициализации (точки или символы)
void ecrypt::set_mod_lineedit_2()
{
    if(ui->pushButton_2->text() == "Отобразить") {
         ui->lineEdit_2->setEchoMode(QLineEdit::Normal);
         ui->pushButton_2->setText("Скрыть");
    }
    else {
         ui->lineEdit_2->setEchoMode(QLineEdit::Password);
         ui->pushButton_2->setText("Отобразить");
    }
}

// Выбор входного файла с помощью диалогового окна Windows
void ecrypt::get_input_file()
{
    QString FileNameIn;

    FileNameIn = QFileDialog::getOpenFileName(this, QString("Открыть файл"), QString(), QString("Все файлы (*.*)"));
    ui->lineEdit_3->setText(FileNameIn);
}

// Выбор выходного файла с помощью диалогового окна Windows
void ecrypt::get_output_file()
{
    QString FileNameOut;

    FileNameOut = QFileDialog::getOpenFileName(this, QString("Открыть файл"), QString(), QString("Все файлы (*.*)"));
    ui->lineEdit_4->setText(FileNameOut);
}

// Экспорт ключа и вектора инициализации в файл key.txt
void ecrypt::export_ket_and_iv()
{
    FILE *fp;

    if((fp = fopen("key.txt", "wb+")) == NULL) {
        QMessageBox::warning(this, "Error!", "Eror opening the file key.txt");
        return;
    }

    fwrite("Key: ", 1, 5, fp);
    fwrite(key, 1, keylen, fp);
    fwrite("\r\nIV: ", 1, 6, fp);
    fwrite(iv, 1, ivlen, fp);

    fclose(fp);

    ui->pushButton_7->setVisible(false);
    QMessageBox::information(this, "Information!", "The secret key and vector initialization stored in the current directory in the file - key.txt");
}

// Интерфейс взаимодействия с библиотекой salsa.h
int
salsa(FILE *fp, FILE *fd, uint8_t *buf, uint8_t *out)
{
    struct salsa_context ctx;
    uint32_t byte;

    salsa_init(&ctx);

    if(salsa_set_key_and_iv(&ctx, key, keylen, iv, ivlen))
        return -1;

    while((byte = fread(buf, 1, block, fp)) > 0) {
        salsa_encrypt(&ctx, buf, byte, out);

        fwrite(out, 1, byte, fd);
    }

    return 0;
}

// Интерфейс взаимодействия с библиотекой rabbit.h
int
rabbit(FILE *fp, FILE *fd, uint8_t *buf, uint8_t *out)
{
    struct rabbit_context ctx;
    uint32_t byte;

    rabbit_init(&ctx);

    if(rabbit_set_key_and_iv(&ctx, key, keylen, iv, ivlen))
        return -1;

    while((byte = fread(buf, 1, block, fp)) > 0) {
        rabbit_encrypt(&ctx, buf, byte, out);

        fwrite(out, 1, byte, fd);
    }

    return 0;
}

// Интерфейс взаимодействия с библиотекой hc128.h
int
hc128(FILE *fp, FILE *fd, uint8_t *buf, uint8_t *out)
{
    struct hc128_context ctx;
    uint32_t byte;

    hc128_init(&ctx);

    if(hc128_set_key_and_iv(&ctx, key, keylen, iv, ivlen))
        return -1;

    while((byte = fread(buf, 1, block, fp)) > 0) {
        hc128_encrypt(&ctx, buf, byte, out);

        fwrite(out, 1, byte, fd);
    }

    return 0;
}

// Интерфейс взаимодействия с библиотекой sosemanuk.h
int
sosemanuk(FILE *fp, FILE *fd, uint8_t *buf, uint8_t *out)
{
    struct sosemanuk_context ctx;
    uint32_t byte;

    sosemanuk_init(&ctx);

    if(sosemanuk_set_key_and_iv(&ctx, key, keylen, iv, ivlen))
        return -1;

    while((byte = fread(buf, 1, block, fp)) > 0) {
        sosemanuk_encrypt(&ctx, buf, byte, out);

        fwrite(out, 1, byte, fd);
    }

    return 0;
}

// Интерфейс взаимодействия с библиотекой grain.h
int
grain(FILE *fp, FILE *fd, uint8_t *buf, uint8_t *out)
{
    struct grain_context ctx;
    uint32_t byte;

    grain_init(&ctx);

    if(grain_set_key_and_iv(&ctx, key, keylen, iv, ivlen))
        return -1;

    while((byte = fread(buf, 1, block, fp)) > 0) {
        grain_encrypt(&ctx, buf, byte, out);

        fwrite(out, 1, byte, fd);
    }

    return 0;
}

// Интерфейс взаимодействия с библиотекой mickey.h
int
mickey(FILE *fp, FILE *fd, uint8_t *buf, uint8_t *out)
{
    struct mickey_context ctx;
    uint32_t byte;

    mickey_init(&ctx);

    if(mickey_set_key_and_iv(&ctx, key, keylen, iv, ivlen))
        return -1;

    while((byte = fread(buf, 1, block, fp)) > 0) {
        mickey_encrypt(&ctx, buf, byte, out);

        fwrite(out, 1, byte, fd);
    }

    return 0;
}

// Интерфейс взаимодействия с библиотекой trivium.h
int
trivium(FILE *fp, FILE *fd, uint8_t *buf, uint8_t *out)
{
    struct trivium_context ctx;
    uint32_t byte;

    trivium_init(&ctx);

    if(trivium_set_key_and_iv(&ctx, key, keylen, iv, ivlen))
        return -1;

    while((byte = fread(buf, 1, block, fp)) > 0) {
        trivium_encrypt(&ctx, buf, byte, out);

        fwrite(out, 1, byte, fd);
    }

    return 0;
}

// Основная функция. Отрабатывает при нажатии на кнопку "Шифрование/Расшифровывание"
void ecrypt::base_func()
{
    FILE *fp, *fd;
    QString k, v, in_file, out_file;
    QByteArray ba;
    uint8_t *buf, *out;
    char *temp;

    if((ui->lineEdit_1->text() == "" || (ui->lineEdit_2->text() == "") || (ui->lineEdit_3->text() == "") || (ui->lineEdit_4->text() == ""))) {
        QMessageBox::information(this, "Error!", "Not all fields are filled!");
        return;
    }

    if((buf = (uint8_t *)malloc(sizeof(uint8_t) * block)) == NULL) {
        QMessageBox::warning(this, "Error!", "Error allocates memory for the buffer data");
        return;
    }

    if((out = (uint8_t *)malloc(sizeof(uint8_t) * block)) == NULL) {
        QMessageBox::warning(this, "Error!", "Error allocates memory for the output buffer data");
        return;
    }

    // Открываем входной файл
    in_file = ui->lineEdit_3->text();
    ba = in_file.toLocal8Bit();
    temp = ba.data();

    if((fp = fopen(temp, "rb+")) == NULL) {
        QMessageBox::warning(this, "Error!", "Error opening the input file");
        return;
    }

    // Открываем выходной файл
    out_file = ui->lineEdit_4->text();
    ba = out_file.toLocal8Bit();
    temp = ba.data();

    if((fd = fopen(temp, "wb+")) == NULL) {
        QMessageBox::warning(this, "Error!", "Error opening the output file");
        return;
    }

    // Получаем секретный ключ из LineEdit_1
    k = ui->lineEdit_1->text();
    ba = k.toLocal8Bit();
    temp = ba.data();
    keylen = k.length();
    memcpy(key, temp, keylen);

    // Получаем вектор инициализации из lineEdit_2
    v = ui->lineEdit_2->text();
    ba = v.toLocal8Bit();
    temp = ba.data();
    ivlen = v.length();
    memcpy(iv, temp, ivlen);

    // Выбор алгоритма
    switch(alg) {
    case 0 : if(salsa(fp, fd, buf, out))
                QMessageBox::warning(this, "Error!", "Salsa function error!");
             break;
    case 1 : if(rabbit(fp, fd, buf, out))
                QMessageBox::warning(this, "Error!", "Rabbit function error!");
             break;
    case 2 : if(hc128(fp, fd, buf, out))
                QMessageBox::warning(this, "Error!", "HC128 function error!");
             break;
    case 3 : if(sosemanuk(fp, fd, buf, out))
                QMessageBox::warning(this, "Error!", "Sosemanuk function error!");
             break;
    case 4 : if(grain(fp, fd, buf, out))
                QMessageBox::warning(this, "Error!", "Grain function error!");
             break;
    case 5 : if(mickey(fp, fd, buf, out))
                QMessageBox::warning(this, "Error!", "Mickey function error!");
             break;
    case 6 : if(trivium(fp, fd, buf, out))
                QMessageBox::warning(this, "Error!", "Trivium function error!");
             break;
    }

    fclose(fp);
    fclose(fd);

    free(buf);
    free(out);

    // Завершающая стадия. Вызов кнопки "Начать снова" и "Экспорт ключа и вектора"
    ui->pushButton_5->setVisible(false);
    ui->pushButton_6->setVisible(true);
    ui->pushButton_7->setVisible(true);
}

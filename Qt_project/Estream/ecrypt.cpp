#include "ecrypt.h"
#include "ui_ecrypt.h"

#define BLOCK   1000000

// Глобальные переменные
uint8_t key[32], iv[16];
int alg = 0;
int keylen, ivlen;

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

// Объединям все структуры проекта eSTREAM в context
union context {
    struct salsa_context salsa;
    struct rabbit_context rabbit;
    struct hc128_context hc128;
    struct sosemanuk_context sosemanuk;
    struct grain_context grain;
    struct mickey_context mickey;
    struct trivium_context trivium;
};

typedef int (*set_t)(void *ctx, uint8_t *key, int keylen, uint8_t *iv, int ivlen);
typedef void (*crypt_t)(void *ctx, uint8_t *buf, uint32_t buflen, uint8_t *out);

// Указатели на функции проекта eSTREAM
set_t set[] = { (set_t)salsa_set_key_and_iv,
                (set_t)rabbit_set_key_and_iv,
                (set_t)hc128_set_key_and_iv,
                (set_t)sosemanuk_set_key_and_iv,
                (set_t)grain_set_key_and_iv,
                (set_t)mickey_set_key_and_iv,
                (set_t)trivium_set_key_and_iv };

crypt_t crypt[] = { (crypt_t)salsa_crypt,
                    (crypt_t)rabbit_crypt,
                    (crypt_t)hc128_crypt,
                    (crypt_t)sosemanuk_crypt,
                    (crypt_t)grain_crypt,
                    (crypt_t)mickey_crypt,
                    (crypt_t)trivium_crypt };

// Функция шифрования/расшифровывания
int
crypt_func(FILE *fp, FILE *fd, void *ctx, int alg)
{
    uint8_t buf[BLOCK], out[BLOCK];
    uint32_t byte;

    if(set[alg](ctx, key, keylen, iv, ivlen))
        return -1;

    while((byte = fread(buf, 1, BLOCK, fp)) > 0) {
        crypt[alg](ctx, buf, byte, out);
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
    union context context;
    char *temp;
    int res;

    if((ui->lineEdit_1->text() == "" || (ui->lineEdit_2->text() == "") || (ui->lineEdit_3->text() == "") || (ui->lineEdit_4->text() == ""))) {
        QMessageBox::information(this, "Error!", "Not all fields are filled!");
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
    case 0 : res = crypt_func(fp, fd, &(context.salsa), alg);
             break;
    case 1 : res = crypt_func(fp, fd, &(context.rabbit), alg);
             break;
    case 2 : res = crypt_func(fp, fd, &(context.hc128), alg);
             break;
    case 3 : res = crypt_func(fp, fd, &(context.sosemanuk), alg);
             break;
    case 4 : res = crypt_func(fp, fd, &(context.grain), alg);
             break;
    case 5 : res = crypt_func(fp, fd, &(context.mickey), alg);
             break;
    case 6 : res = crypt_func(fp, fd, &(context.trivium), alg);
             break;
    default: QMessageBox::warning(this, "Error!", "No such algorithm!");
             return;
    }

    fclose(fp);
    fclose(fd);

    if(res == -1)
        QMessageBox::warning(this, "Error!", "Error in crypting!");

    // Завершающая стадия. Вызов кнопки "Начать снова" и "Экспорт ключа и вектора"
    ui->pushButton_5->setVisible(false);
    ui->pushButton_6->setVisible(true);
    ui->pushButton_7->setVisible(true);
}

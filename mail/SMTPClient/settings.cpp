/*
 * The file encryption settings. Auxiliary dialog windows.
*/

#include "settings.h"
#include "ui_settings.h"

Settings::Settings(int security, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Settings)
{
    ui->setupUi(this);

    // Обрабатываем события выбора алгоритма и режима
    connect(ui->comboBox_1, SIGNAL(currentIndexChanged(int)), this, SLOT(slotMode()));
    connect(ui->comboBox_2, SIGNAL(currentIndexChanged(int)), this, SLOT(slotSelectAlgorithm()));

    // Обрабатываем собития нажатия кнопок
    connect(ui->pushButton_1, SIGNAL(clicked()), this, SLOT(slotCloseForm()));
    connect(ui->pushButton_2, SIGNAL(clicked()), this, SLOT(slotModeSecretKey()));

    // В зависимости от режима активируем те или иные поля
    if(security == -1) {
        ui->comboBox_2->setEnabled(false);
        ui->lineEdit->setEnabled(false);
    }
    else {
        ui->comboBox_1->setCurrentIndex(1);
        ui->comboBox_2->setCurrentIndex(security);
    }
}

Settings::~Settings()
{
    delete ui;
}

// Меняем режим отображения поля секретного ключа
void Settings::slotModeSecretKey(void)
{
    if(ui->pushButton_2->text() == "Отобразить") {
        ui->lineEdit->setEchoMode(QLineEdit::Normal);
        ui->pushButton_2->setText("Скрыть");
    }
    else {
        ui->lineEdit->setEchoMode(QLineEdit::Password);
        ui->pushButton_2->setText("Отобразить");
    }
}

// Закрываем форму и отправляем данные в основную форму
void Settings::slotCloseForm(void)
{
    QString Password;
    int mode;

    ClientSMTP *Client;
    Client = new ClientSMTP();

    mode = ui->comboBox_1->currentIndex();

    if(mode == 1) {
        mode = ui->comboBox_2->currentIndex();
        Password = ui->lineEdit->text();

        if(Password.length() == 0) {
            QMessageBox::warning(this, QString::fromUtf8("Ошибка!"), QString::fromUtf8("Не все поля заполнены!"));
            return;
        }
    }
    else
        mode = -1;

    connect(this, SIGNAL(sendData(QString, int)), Client, SLOT(slotRecieveData(QString, int)));
    emit sendData(Password, mode);

    delete Client;
    close();
}

// В зависимости от режима (шифрование/открытый) активируем дополнительные настройки
void Settings::slotMode(void)
{
    if(ui->comboBox_1->currentIndex() == 1) {
        ui->comboBox_2->setEnabled(true);
        ui->lineEdit->setEnabled(true);
    }
    else {
        ui->comboBox_2->setEnabled(false);
        ui->lineEdit->setEnabled(false);
    }
}

// В зависимости от выбранного алгоритма меняем длину поля для ввода секретного ключа
void Settings::slotSelectAlgorithm(void)
{
    switch(ui->comboBox_2->currentIndex()) {
        case 0 : ui->lineEdit->setMaxLength(32);
                 break;
        case 1 : ui->lineEdit->setMaxLength(16);
                 break;
        case 2 : ui->lineEdit->setMaxLength(16);
                 break;
        case 3 : ui->lineEdit->setMaxLength(32);
                 break;
        case 4 : ui->lineEdit->setMaxLength(16);
                 break;
        case 5 : ui->lineEdit->setMaxLength(10);
                 break;
        case 6 : ui->lineEdit->setMaxLength(10);
                 break;
        }
}

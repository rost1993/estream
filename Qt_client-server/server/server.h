// Заголовочный файл сервера. Содержит набор базовых функций и переменных

#ifndef SERVER_H
#define SERVER_H

#include <QTime>
#include <QColor>
#include <QDialog>
#include <QString>
#include <QTcpServer>
#include <QTcpSocket>
#include <QMessageBox>

#include <stdlib.h>
#include <stdint.h>
#include "../lib/estream.h"

namespace Ui {
class Server;
}

class Server : public QDialog
{
    Q_OBJECT

public:
    explicit Server(QWidget *parent = 0);
    ~Server();

private:
    Ui::Server *ui;
    QTcpServer *server;
    QTcpSocket *client;
    QString key;
    quint16 nextBlockSize;
    int security;

private slots:
    void slotStartStopServer();
    void slotConnectionClient();
    void slotReadClient();
    void slotDisconnectionClient();
    void slotSendToClient();
    void slotCrypt();
};

#endif // SERVER_H

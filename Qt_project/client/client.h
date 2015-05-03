#ifndef CLIENT_H
#define CLIENT_H

#include <QTime>
#include <QColor>
#include <QDialog>
#include <QTcpSocket>
#include <QMessageBox>
#include <QAbstractSocket>

#include <stdlib.h>
#include <stdint.h>
#include "settings.h"
#include "../lib/estream.h"

namespace Ui {
class Client;
}

class Client : public QDialog
{
    Q_OBJECT

public:
    explicit Client(QWidget *parent = 0);
    ~Client();

private:
    Ui::Client *ui;
    QTcpSocket *client;
    quint16 nextBlockSize;

private slots:
    void slotConnectToServer();
    void slotConnected();
    void slotDisconnectToServer();
    void slotReadServer();
    void slotError(QAbstractSocket::SocketError);
    void slotSendToServer();
    void slotNewFormSettings();
    void slotCrypt();
    void slotSendKeyToServer();
    void slotRecieveData(QString str, int alg);
};

#endif // CLIENT_H

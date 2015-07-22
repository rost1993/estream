/*
 * Copyright (C) 2015, Rostislav Gashin
 * <rostislav-gashin@yandex.ru>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the program. If not, see <http://www.gnu.org/licenses/lgpl-3.0.html>
 * ------------------------------------
 * POP3 client. It uses the POP3 protocol handler.
 * ------------------------------------
 * Developed: Rostislav Gashin (rost1993). The State University of Syktyvkar (Amplab).
 * Russia, Komi Republic, Syktyvkar - 21.07.2015.
 *
*/

#ifndef CLIENTPOP3_H
#define CLIENTPOP3_H

#include <QRegExp>
#include <QMainWindow>
#include <QMessageBox>

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "pop3.h"
#include "settings.h"
#include "../lib/estream.h"

namespace Ui {
class ClientPOP3;
}

class ClientPOP3 : public QMainWindow
{
    Q_OBJECT

public:
    explicit ClientPOP3(QWidget *parent = 0);
    ~ClientPOP3();

private:
    Ui::ClientPOP3 *ui;

    POP3 *Client;
    QString POP3Server;

private slots:
    void slotModePasswordClient(void);
    void slotConnectToServer(void);
    void slotDisconnectToServer(void);
    void slotReceiveMessageList(void);
    void slotReceiveMessage(void);
    void slotDecryptMessage(void);
    void slotNewFormSettings(void);
    void slotRecieveData(const QString Pass, int alg);
};

#endif // CLIENTPOP3_H

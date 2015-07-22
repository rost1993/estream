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
 * SMTP client. It uses the SMTP protocol handler.
 * ------------------------------------
 * Developed: Rostislav Gashin (rost1993). The State University of Syktyvkar (Amplab).
 * Russia, Komi Republic, Syktyvkar - 21.07.2015.
 *
*/

#ifndef CLIENTSMTP_H
#define CLIENTSMTP_H

#include <QRegExp>
#include <QMainWindow>
#include <QMessageBox>
#include <QSslSocket>

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "settings.h"
#include "../src/SmtpMime"
#include "../lib/estream.h"

namespace Ui {
class ClientSMTP;
}

class ClientSMTP : public QMainWindow
{
    Q_OBJECT

public:
    explicit ClientSMTP(QWidget *parent = 0);
    ~ClientSMTP();

private:
    Ui::ClientSMTP *ui;

    QString SenderPost;
    QString SmtpServer;
    QString SenderSubject;
    QString SenderMessage;
    QString RecepientPost;

private slots:
    void slotModePasswordClient(void);
    void slotAutorizationToServer(void);
    void slotSmtpServerCooperation(void);
    void slotClearAllField(void);
    void slotEncryptMessage(void);
    void slotNewFormSettings(void);
    void slotRecieveData(const QString Pass, int alg);
};

#endif // CLIENTSMTP_H

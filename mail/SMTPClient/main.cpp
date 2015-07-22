#include "clientsmtp.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    ClientSMTP w;
    w.show();

    return a.exec();
}

#include "ecrypt.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    ecrypt w;
    w.show();

    return a.exec();
}

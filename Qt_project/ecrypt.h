#ifndef ECRYPT_H
#define ECRYPT_H

#include <QMainWindow>

namespace Ui {
class ecrypt;
}

class ecrypt : public QMainWindow
{
    Q_OBJECT

public:
    explicit ecrypt(QWidget *parent = 0);
    ~ecrypt();

public slots:
   void base_func();
   void set_mod_lineedit_1();
   void set_mod_lineedit_2();
   void get_input_file();
   void get_output_file();
   void select_algorithm();
   void new_form();
   void export_ket_and_iv();

private:
    Ui::ecrypt *ui;
};

#endif // ECRYPT_H

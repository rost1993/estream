#-------------------------------------------------
#
# Project created by QtCreator 2015-03-22T13:40:33
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Estream
TEMPLATE = app


SOURCES += main.cpp\
        ecrypt.cpp \
    ../lib/grain.cpp \
    ../lib/hc128.cpp \
    ../lib/mickey.cpp \
    ../lib/rabbit.cpp \
    ../lib/salsa.cpp \
    ../lib/sosemanuk.cpp \
    ../lib/trivium.cpp

HEADERS  += ecrypt.h \
    ../lib/estream.h \
    ../lib/grain.h \
    ../lib/hc128.h \
    ../lib/macro.h \
    ../lib/mickey.h \
    ../lib/rabbit.h \
    ../lib/salsa.h \
    ../lib/sosemanuk.h \
    ../lib/trivium.h

FORMS    += ecrypt.ui

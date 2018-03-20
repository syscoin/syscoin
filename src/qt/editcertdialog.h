#ifndef EDITCERTDIALOG_H
#define EDITCERTDIALOG_H

#include <QDialog>

namespace Ui {
    class EditCertIssuerDialog;
}
class CertIssuerTableModel;

QT_BEGIN_NAMESPACE
class QDataWidgetMapper;
QT_END_NAMESPACE

/** Dialog for editing an address and associated information.
 */
class EditCertIssuerDialog : public QDialog
{
    Q_OBJECT

public:
    enum Mode {
        NewCertItem,
        NewCertIssuer,
        EditCertItem,
        EditCertIssuer
    };

    explicit EditCertIssuerDialog(Mode mode, QWidget *parent = 0);
    ~EditCertIssuerDialog();

    void setModel(CertIssuerTableModel *model);
    void loadRow(int row);

    QString getCertIssuer() const;
    void setCertIssuer(const QString &cert);

public slots:
    void accept();

private:
    bool saveCurrentRow();

    Ui::EditCertIssuerDialog *ui;
    QDataWidgetMapper *mapper;
    Mode mode;
    CertIssuerTableModel *model;

    QString cert;
};

#endif // EDITCERTDIALOG_H

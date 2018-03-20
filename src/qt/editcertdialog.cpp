#include "editcertdialog.h"
#include "ui_editcertdialog.h"

#include "certtablemodel.h"
#include "guiutil.h"

#include <QDataWidgetMapper>
#include <QMessageBox>

EditCertIssuerDialog::EditCertIssuerDialog(Mode mode, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EditCertIssuerDialog), mapper(0), mode(mode), model(0)
{
    ui->setupUi(this);

    GUIUtil::setupAddressWidget(ui->certEdit, this);

    switch(mode)
    {
    case NewCertItem:
        setWindowTitle(tr("New certificate"));
        //ui->certEdit->setEnabled(false);
        break;
    case NewCertIssuer:
        setWindowTitle(tr("New cert"));
        break;
    case EditCertItem:
        setWindowTitle(tr("Edit certificate"));
        break;
    case EditCertIssuer:
        setWindowTitle(tr("Edit cert"));
        break;
    }

    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
}

EditCertIssuerDialog::~EditCertIssuerDialog()
{
    delete ui;
}

void EditCertIssuerDialog::setModel(CertIssuerTableModel *model)
{
    this->model = model;
    if(!model) return;

    mapper->setModel(model);
    mapper->addMapping(ui->labelEdit, CertIssuerTableModel::Title);
    mapper->addMapping(ui->certEdit, CertIssuerTableModel::Name);
}

void EditCertIssuerDialog::loadRow(int row)
{
    mapper->setCurrentIndex(row);
}

bool EditCertIssuerDialog::saveCurrentRow()
{
    if(!model) return false;

    switch(mode)
    {
    case NewCertItem:
    case NewCertIssuer:
        cert = model->addRow(
                mode == NewCertIssuer ? CertIssuerTableModel::CertIssuer : CertIssuerTableModel::CertItem,
                ui->labelEdit->text(),
                ui->certEdit->text(),
                ui->certEdit->text());
        break;
    case EditCertItem:
    case EditCertIssuer:
        if(mapper->submit())
        {
            cert = ui->certEdit->text();
        }
        break;
    }
    return !cert.isEmpty();
}

void EditCertIssuerDialog::accept()
{
    if(!model) return;

    if(!saveCurrentRow())
    {
        switch(model->getEditStatus())
        {
        case CertIssuerTableModel::OK:
            // Failed with unknown reason. Just reject.
            break;
        case CertIssuerTableModel::NO_CHANGES:
            // No changes were made during edit operation. Just reject.
            break;
        case CertIssuerTableModel::INVALID_CERT:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered cert \"%1\" is not a valid Syscoin cert.").arg(ui->certEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case CertIssuerTableModel::DUPLICATE_CERT:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered cert \"%1\" is already taken.").arg(ui->certEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case CertIssuerTableModel::WALLET_UNLOCK_FAILURE:
            QMessageBox::critical(this, windowTitle(),
                tr("Could not unlock wallet."),
                QMessageBox::Ok, QMessageBox::Ok);
            break;

        }
        return;
    }
    QDialog::accept();
}

QString EditCertIssuerDialog::getCertIssuer() const
{
    return cert;
}

void EditCertIssuerDialog::setCertIssuer(const QString &cert)
{
    this->cert = cert;
    ui->certEdit->setText(cert);
}

#include "editaliasdialog.h"
#include "ui_editaliasdialog.h"

#include "aliastablemodel.h"
#include "guiutil.h"
#include "walletmodel.h"
#include "syscoingui.h"
#include "ui_interface.h"
#include <QDataWidgetMapper>
#include <QMessageBox>
#include "rpc/server.h"
using namespace std;

extern CRPCTable tableRPC;
EditAliasDialog::EditAliasDialog(Mode mode, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EditAliasDialog), mapper(0), mode(mode), model(0)
{
    ui->setupUi(this);

	ui->transferEdit->setVisible(false);
	ui->transferLabel->setVisible(false);
	ui->transferDisclaimer->setText(tr("<font color='blue'>Transfering your alias will also transfer ownership all of your syscoin services that use this alias, the new owner can use these services by clicking on import button from the alias list screen which will import alias key into their wallet</font>"));
	ui->transferDisclaimer->setVisible(false);
	ui->safeSearchDisclaimer->setText(tr("<font color='blue'>Is this alias safe to search? Anything that can be considered offensive to someone should be set to <b>No</b> here. If you do create an alias that is offensive and do not set this option to <b>No</b> your alias will be banned!</font>"));
	ui->expiryEdit->clear();
	ui->expiryEdit->addItem(tr("1 Year"),"1");
	ui->expiryEdit->addItem(tr("2 Years"),"2");
	ui->expiryEdit->addItem(tr("3 Years"),"3");
	ui->expiryEdit->addItem(tr("4 Years"),"4");
	ui->expiryEdit->addItem(tr("5 Years"),"5");
	ui->expiryDisclaimer->setText(tr("<font color='blue'>Set the length of time to keep your alias from expiring. The longer you wish to keep it alive the more fees you will pay to create or update this alias. The formula for the fee is 0.2 SYS * years * years.</font>"));
    ui->privateDisclaimer->setText(tr("<font color='blue'>This is to private profile information which is encrypted and only available to you. This is useful for when sending notes to a merchant through the payment screen so you don't have to type it out everytime.</font>"));
	ui->publicDisclaimer->setText(tr("<font color='blue'>This is public profile information that anyone on the network can see. Fill this in with things you would like others to know about you.</font>"));
	switch(mode)
    {
    case NewDataAlias:
        setWindowTitle(tr("New Data Alias"));
        break;
    case NewAlias:
        setWindowTitle(tr("New Alias"));
        break;
    case EditDataAlias:
        setWindowTitle(tr("Edit Data Alias"));
		ui->aliasEdit->setEnabled(false);
        break;
    case EditAlias:
        setWindowTitle(tr("Edit Alias"));
		ui->aliasEdit->setEnabled(false);
        break;
    case TransferAlias:
        setWindowTitle(tr("Transfer Alias"));
		ui->aliasEdit->setEnabled(false);
		ui->nameEdit->setEnabled(false);
		ui->safeSearchEdit->setEnabled(false);
		ui->safeSearchDisclaimer->setVisible(false);
		ui->privateEdit->setEnabled(false);
		ui->transferEdit->setVisible(true);
		ui->transferLabel->setVisible(true);
		ui->transferDisclaimer->setVisible(true);
		ui->tabWidget->setCurrentIndex(1);
        break;
    }
    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
}

EditAliasDialog::~EditAliasDialog()
{
    delete ui;
}
void EditAliasDialog::on_cancelButton_clicked()
{
    reject();
}
void EditAliasDialog::on_okButton_clicked()
{
    mapper->submit();
    accept();
}
void EditAliasDialog::setModel(WalletModel* walletModel, AliasTableModel *model)
{
    this->model = model;
	this->walletModel = walletModel;
    if(!model) return;

    mapper->setModel(model);
	mapper->addMapping(ui->aliasEdit, AliasTableModel::Name);
    mapper->addMapping(ui->nameEdit, AliasTableModel::Value);
	mapper->addMapping(ui->privateEdit, AliasTableModel::PrivValue);
	
    
}

void EditAliasDialog::loadRow(int row)
{
    mapper->setCurrentIndex(row);
	const QModelIndex tmpIndex;
	if(model)
	{
		QModelIndex indexSafeSearch= model->index(row, AliasTableModel::SafeSearch, tmpIndex);
		if(indexSafeSearch.isValid())
		{
			QString safeSearchStr = indexSafeSearch.data(AliasTableModel::SafeSearchRole).toString();
			ui->safeSearchEdit->setCurrentIndex(ui->safeSearchEdit->findText(safeSearchStr));
		}
	}
}

bool EditAliasDialog::saveCurrentRow()
{

    if(!model || !walletModel) return false;
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if(!ctx.isValid())
    {
		model->editStatus = AliasTableModel::WALLET_UNLOCK_FAILURE;
        return false;
    }
	UniValue params(UniValue::VARR);
	string strMethod;
    switch(mode)
    {
    case NewDataAlias:
    case NewAlias:
        if (ui->aliasEdit->text().trimmed().isEmpty()) {
            ui->aliasEdit->setText("");
            QMessageBox::information(this, windowTitle(),
            tr("Empty name for Alias not allowed. Please try again"),
                QMessageBox::Ok, QMessageBox::Ok);
            return false;
        }
		strMethod = string("aliasnew");
        params.push_back(ui->aliasEdit->text().trimmed().toStdString());
		params.push_back(ui->nameEdit->toPlainText().toStdString());
		params.push_back(ui->privateEdit->toPlainText().toStdString());
		params.push_back(ui->safeSearchEdit->currentText().toStdString());
		params.push_back(ui->expiryEdit->itemData(ui->expiryEdit->currentIndex()).toString().toStdString());
		try {
            UniValue result = tableRPC.execute(strMethod, params);
			if (result.type() != UniValue::VNULL)
			{
				alias = ui->nameEdit->toPlainText() + ui->aliasEdit->text();
					
			}
		}
		catch (UniValue& objError)
		{
			string strError = find_value(objError, "message").get_str();
			QMessageBox::critical(this, windowTitle(),
			tr("Error creating new Alias: \"%1\"").arg(QString::fromStdString(strError)),
				QMessageBox::Ok, QMessageBox::Ok);
			break;
		}
		catch(std::exception& e)
		{
			QMessageBox::critical(this, windowTitle(),
				tr("General exception creating new Alias"),
				QMessageBox::Ok, QMessageBox::Ok);
			break;
		}							

        break;
    case EditDataAlias:
    case EditAlias:
        if(mapper->submit())
        {
			strMethod = string("aliasupdate");
			params.push_back(ui->aliasEdit->text().toStdString());
			params.push_back(ui->nameEdit->toPlainText().toStdString());
			params.push_back(ui->privateEdit->toPlainText().toStdString());
			params.push_back(ui->safeSearchEdit->currentText().toStdString());	
			params.push_back("");
			params.push_back(ui->expiryEdit->itemData(ui->expiryEdit->currentIndex()).toString().toStdString());
			try {
				UniValue result = tableRPC.execute(strMethod, params);
				if (result.type() != UniValue::VNULL)
				{
				
					alias = ui->nameEdit->toPlainText() + ui->aliasEdit->text();
						
				}
			}
			catch (UniValue& objError)
			{
				string strError = find_value(objError, "message").get_str();
				QMessageBox::critical(this, windowTitle(),
				tr("Error updating Alias: \"%1\"").arg(QString::fromStdString(strError)),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}
			catch(std::exception& e)
			{
				QMessageBox::critical(this, windowTitle(),
					tr("General exception updating Alias"),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}	
        }
        break;
    case TransferAlias:
        if(mapper->submit())
        {
			strMethod = string("aliasupdate");
			params.push_back(ui->aliasEdit->text().toStdString());
			params.push_back(ui->nameEdit->toPlainText().toStdString());
			params.push_back(ui->privateEdit->toPlainText().toStdString());
			params.push_back(ui->safeSearchEdit->currentText().toStdString());
			params.push_back(ui->transferEdit->text().toStdString());
			params.push_back(ui->expiryEdit->itemData(ui->expiryEdit->currentIndex()).toString().toStdString());
			try {
				UniValue result = tableRPC.execute(strMethod, params);
				if (result.type() != UniValue::VNULL)
				{

					alias = ui->nameEdit->toPlainText() + ui->aliasEdit->text()+ui->transferEdit->text();
						
				}
			}
			catch (UniValue& objError)
			{
				string strError = find_value(objError, "message").get_str();
				QMessageBox::critical(this, windowTitle(),
                tr("Error transferring Alias: \"%1\"").arg(QString::fromStdString(strError)),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}
			catch(std::exception& e)
			{
				QMessageBox::critical(this, windowTitle(),
                    tr("General exception transferring Alias"),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}	
        }
        break;
    }
    return !alias.isEmpty();
}

void EditAliasDialog::accept()
{
    if(!model) return;

    if(!saveCurrentRow())
    {
        switch(model->getEditStatus())
        {
        case AliasTableModel::OK:
            // Failed with unknown reason. Just reject.
            break;
        case AliasTableModel::NO_CHANGES:
            // No changes were made during edit operation. Just reject.
            break;
        case AliasTableModel::INVALID_ALIAS:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered alias \"%1\" is not a valid Syscoin Alias.").arg(ui->aliasEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case AliasTableModel::DUPLICATE_ALIAS:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered alias \"%1\" is already taken.").arg(ui->aliasEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case AliasTableModel::WALLET_UNLOCK_FAILURE:
            QMessageBox::critical(this, windowTitle(),
                tr("Could not unlock wallet."),
                QMessageBox::Ok, QMessageBox::Ok);
            break;

        }
        return;
    }
    QDialog::accept();
}

QString EditAliasDialog::getAlias() const
{
    return alias;
}

void EditAliasDialog::setAlias(const QString &alias)
{
    this->alias = alias;
    ui->aliasEdit->setText(alias);
}

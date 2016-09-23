#include "editcertdialog.h"
#include "ui_editcertdialog.h"

#include "certtablemodel.h"
#include "guiutil.h"
#include "walletmodel.h"
#include "syscoingui.h"
#include "ui_interface.h"
#include <QDataWidgetMapper>
#include <QMessageBox>
#include "rpcserver.h"
#include <QStandardItemModel>
#include "qcomboboxdelegate.h"
#include <boost/algorithm/string.hpp>
#include <QSettings>
using namespace std;

extern const CRPCTable tableRPC;
extern bool getCategoryList(vector<string>& categoryList);
EditCertDialog::EditCertDialog(Mode mode, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EditCertDialog), mapper(0), mode(mode), model(0)
{
    ui->setupUi(this);
	ui->certLabel->setVisible(true);
	ui->certEdit->setVisible(true);
	ui->certEdit->setEnabled(false);
	ui->certDataEdit->setVisible(true);
	ui->certDataEdit->setEnabled(true);
	ui->certDataLabel->setVisible(true);
	ui->certDataEdit->setStyleSheet("color: rgb(0, 0, 0); background-color: rgb(255, 255, 255)");
	ui->privateLabel->setVisible(true);
	ui->privateBox->setVisible(true);
	ui->transferLabel->setVisible(false);
	ui->transferEdit->setVisible(false);
	ui->privateBox->addItem(tr("Yes"));
	ui->privateBox->addItem(tr("No"));
	ui->transferDisclaimer->setText(tr("<font color='blue'>Enter the alias of the recipient of this certificate</font>"));
    ui->transferDisclaimer->setVisible(false);
	
	loadAliases();
	loadCategories();
	connect(ui->aliasEdit,SIGNAL(currentIndexChanged(const QString&)),this,SLOT(aliasChanged(const QString&)));
	
	QSettings settings;
	QString defaultCertAlias;
	int aliasIndex;
	switch(mode)
    {
    case NewCert:
		ui->certLabel->setVisible(false);
		ui->certEdit->setVisible(false);
		
		defaultCertAlias = settings.value("defaultCertAlias", "").toString();
		aliasIndex = ui->aliasEdit->findText(defaultCertAlias);
		if(aliasIndex >= 0)
			ui->aliasEdit->setCurrentIndex(aliasIndex);
        setWindowTitle(tr("New Cert"));
        break;
    case EditCert:
        setWindowTitle(tr("Edit Cert"));
		
        break;
    case TransferCert:
        setWindowTitle(tr("Transfer Cert"));
		ui->nameEdit->setEnabled(false);
		ui->certDataEdit->setVisible(false);
		ui->certDataEdit->setEnabled(false);
		ui->certDataLabel->setVisible(false);
		ui->privateLabel->setVisible(false);
		ui->privateBox->setVisible(false);
		ui->transferLabel->setVisible(true);
		ui->transferEdit->setVisible(true);
		ui->transferDisclaimer->setVisible(true);
		ui->aliasDisclaimer->setVisible(false);
		ui->aliasEdit->setEnabled(false);
        break;
    }
    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
	aliasChanged(ui->aliasEdit->currentText());
	if(mode == TransferCert)
	{
		ui->safeSearchEdit->setEnabled(false);
		ui->safeSearchDisclaimer->setVisible(false);
		ui->categoryEdit->setEnabled(false);
	}
	
}
	
void EditCertDialog::addParentItem( QStandardItemModel * model, const QString& text, const QVariant& data )
{
	QList<QStandardItem*> lst = model->findItems(text,Qt::MatchExactly);
	for(unsigned int i=0; i<lst.count(); ++i )
	{ 
		if(lst[i]->data(Qt::UserRole) == data)
			return;
	}
    QStandardItem* item = new QStandardItem( text );
	item->setData( data, Qt::UserRole );
    item->setData( "parent", Qt::AccessibleDescriptionRole );
    QFont font = item->font();
    font.setBold( true );
    item->setFont( font );
    model->appendRow( item );
}

void EditCertDialog::addChildItem( QStandardItemModel * model, const QString& text, const QVariant& data )
{
	QList<QStandardItem*> lst = model->findItems(text,Qt::MatchExactly);
	for(unsigned int i=0; i<lst.count(); ++i )
	{ 
		if(lst[i]->data(Qt::UserRole) == data)
			return;
	}

    QStandardItem* item = new QStandardItem( text + QString( 4, QChar( ' ' ) ) );
    item->setData( data, Qt::UserRole );
    item->setData( "child", Qt::AccessibleDescriptionRole );
    model->appendRow( item );
}
void EditCertDialog::loadCategories()
{
    QStandardItemModel * model = new QStandardItemModel;
	vector<string> categoryList;
	if(!getCategoryList(categoryList))
	{
		return;
	}
	addParentItem(model, tr("certificates"), tr("certificates"));
	for(unsigned int i = 0;i< categoryList.size(); i++)
	{
		vector<string> categories;
		boost::split(categories,categoryList[i],boost::is_any_of(">"));
		if(categories.size() > 0 && categories.size() <= 2)
		{
			for(unsigned int j = 0;j< categories.size(); j++)
			{
				boost::algorithm::trim(categories[j]);
				if(categories[0] != "certificates")
					continue;
				if(j == 1)
				{
					addChildItem(model, QString::fromStdString(categories[1]), QVariant(QString::fromStdString(categoryList[i])));
				}
			}
		}
	}
    ui->categoryEdit->setModel(model);
    ui->categoryEdit->setItemDelegate(new ComboBoxDelegate);
}
void EditCertDialog::aliasChanged(const QString& alias)
{
	string strMethod = string("aliasinfo");
    UniValue params(UniValue::VARR); 
	params.push_back(alias.toStdString());
	UniValue result ;
	string name_str;
	int expired = 0;
	bool safeSearch;
	int safetyLevel;
	try {
		result = tableRPC.execute(strMethod, params);

		if (result.type() == UniValue::VOBJ)
		{
			name_str = "";
			safeSearch = false;
			expired = safetyLevel = 0;
			const UniValue& o = result.get_obj();
			name_str = "";
			safeSearch = false;
			expired = safetyLevel = 0;


	
			const UniValue& name_value = find_value(o, "name");
			if (name_value.type() == UniValue::VSTR)
				name_str = name_value.get_str();		
			const UniValue& expired_value = find_value(o, "expired");
			if (expired_value.type() == UniValue::VNUM)
				expired = expired_value.get_int();
			const UniValue& ss_value = find_value(o, "safesearch");
			if (ss_value.type() == UniValue::VSTR)
				safeSearch = ss_value.get_str() == "Yes";	
			const UniValue& sl_value = find_value(o, "safetylevel");
			if (sl_value.type() == UniValue::VNUM)
				safetyLevel = sl_value.get_int();
			if(!safeSearch || safetyLevel > 0)
			{
				setCertNotSafeBecauseOfAlias(QString::fromStdString(name_str));
			}
			else
				resetSafeSearch();

			if(expired != 0)
			{
				ui->aliasDisclaimer->setText(tr("<font color='red'>This alias has expired, please choose another one</font>"));					
			}
			else
				ui->aliasDisclaimer->setText(tr("<font color='blue'>Select an alias to own this certificate</font>"));	
		}
		else
		{
			resetSafeSearch();
			ui->aliasDisclaimer->setText(tr("<font color='blue'>Select an alias to own this certificate</font>"));	
		}
	}
	catch (UniValue& objError)
	{
		resetSafeSearch();
		ui->aliasDisclaimer->setText(tr("<font color='blue'>Select an alias to own this certificate</font>"));	
	}
	catch(std::exception& e)
	{
		resetSafeSearch();
		ui->aliasDisclaimer->setText(tr("<font color='blue'>Select an alias to own this certificate</font>"));	
	}  
}
void EditCertDialog::setCertNotSafeBecauseOfAlias(const QString &alias)
{
	ui->safeSearchEdit->setCurrentIndex(ui->safeSearchEdit->findText("No"));
	ui->safeSearchEdit->setEnabled(false);
	ui->safeSearchDisclaimer->setText(tr("<font color='red'><b>%1</b> is not safe to search so this setting can only be set to No").arg(alias));
}
void EditCertDialog::resetSafeSearch()
{
	ui->safeSearchEdit->setEnabled(true);
	ui->safeSearchDisclaimer->setText(tr("<font color='blue'>Is this cert safe to search? Anything that can be considered offensive to someone should be set to <b>No</b> here. If you do create a cert that is offensive and do not set this option to <b>No</b> your cert will be banned!</font>"));
	
}
void EditCertDialog::loadAliases()
{
	ui->aliasEdit->clear();
	string strMethod = string("aliaslist");
    UniValue params(UniValue::VARR); 
	UniValue result ;
	string name_str;
	int expired = 0;
	try {
		result = tableRPC.execute(strMethod, params);

		if (result.type() == UniValue::VARR)
		{
			name_str = "";
			expired = 0;


	
			const UniValue &arr = result.get_array();
		    for (unsigned int idx = 0; idx < arr.size(); idx++) {
			    const UniValue& input = arr[idx];
				if (input.type() != UniValue::VOBJ)
					continue;
				const UniValue& o = input.get_obj();
				name_str = "";
				expired = 0;
		
				const UniValue& name_value = find_value(o, "name");
				if (name_value.type() == UniValue::VSTR)
					name_str = name_value.get_str();		
				const UniValue& expired_value = find_value(o, "expired");
				if (expired_value.type() == UniValue::VNUM)
					expired = expired_value.get_int();
				if(expired == 0)
				{
					QString name = QString::fromStdString(name_str);
					ui->aliasEdit->addItem(name);					
				}				
			}
		}
	}
	catch (UniValue& objError)
	{
		string strError = find_value(objError, "message").get_str();
		QMessageBox::critical(this, windowTitle(),
			tr("Could not refresh alias list: %1").arg(QString::fromStdString(strError)),
				QMessageBox::Ok, QMessageBox::Ok);
	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
			tr("There was an exception trying to refresh the alias list: ") + QString::fromStdString(e.what()),
				QMessageBox::Ok, QMessageBox::Ok);
	}         
 
}
EditCertDialog::~EditCertDialog()
{
    delete ui;
}

void EditCertDialog::setModel(WalletModel* walletModel, CertTableModel *model)
{
    this->model = model;
	this->walletModel = walletModel;
    if(!model) return;

    mapper->setModel(model);
	mapper->addMapping(ui->certEdit, CertTableModel::Name);
    mapper->addMapping(ui->nameEdit, CertTableModel::Title);
	mapper->addMapping(ui->certDataEdit, CertTableModel::Data);
	mapper->addMapping(ui->categoryEdit, CertTableModel::Category);
    
}

void EditCertDialog::loadRow(int row, const QString &privatecert)
{
    mapper->setCurrentIndex(row);
	const QModelIndex tmpIndex;
	if(model)
	{
		QModelIndex indexAlias = model->index(row, CertTableModel::Alias, tmpIndex);
		QModelIndex indexSafeSearch= model->index(row, CertTableModel::SafeSearch, tmpIndex);
		QModelIndex indexCategory = model->index(row, CertTableModel::Category, tmpIndex);
		if(indexAlias.isValid())
		{
			QString aliasStr = indexAlias.data(CertTableModel::AliasRole).toString();
			ui->aliasEdit->setCurrentIndex(ui->aliasEdit->findText(aliasStr));
		}
		if(indexSafeSearch.isValid() && ui->safeSearchEdit->isEnabled())
		{
			QString safeSearchStr = indexSafeSearch.data(CertTableModel::SafeSearchRole).toString();
			ui->safeSearchEdit->setCurrentIndex(ui->safeSearchEdit->findText(safeSearchStr));
		}
		if(indexCategory.isValid())
		{
			QString categoryStr = indexCategory.data(CertTableModel::CategoryRole).toString();
			int index = ui->categoryEdit->findData(QVariant(categoryStr));
			if ( index != -1 ) 
			{ 
				ui->categoryEdit->setCurrentIndex(index);
			}
		}
	}
	if(privatecert == tr("Yes"))
		ui->privateBox->setCurrentIndex(0);
	else
		ui->privateBox->setCurrentIndex(1);

}

bool EditCertDialog::saveCurrentRow()
{

    if(!model || !walletModel) return false;
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if(!ctx.isValid())
    {
		model->editStatus = CertTableModel::WALLET_UNLOCK_FAILURE;
        return false;
    }
	UniValue params(UniValue::VARR);
	string strMethod;
    switch(mode)
    {
    case NewCert:
        if (ui->nameEdit->text().trimmed().isEmpty()) {
            ui->nameEdit->setText("");
            QMessageBox::information(this, windowTitle(),
            tr("Empty name for Cert not allowed. Please try again"),
                QMessageBox::Ok, QMessageBox::Ok);
            return false;
        }
		strMethod = string("certnew");
		params.push_back(ui->aliasEdit->currentText().toStdString());
		params.push_back(ui->nameEdit->text().toStdString());
		params.push_back(ui->certDataEdit->toPlainText().toStdString());
		params.push_back(ui->privateBox->currentText() == QString("Yes")? "1": "0");
		params.push_back(ui->safeSearchEdit->currentText().toStdString());
		if(ui->categoryEdit->currentIndex() >= 0)
			params.push_back(ui->categoryEdit->itemData(ui->categoryEdit->currentIndex(), Qt::UserRole).toString().toStdString());
		else
			params.push_back(ui->categoryEdit->currentText().toStdString());
		try {
            UniValue result = tableRPC.execute(strMethod, params);
			if (result.type() != UniValue::VNULL)
			{
				cert = ui->nameEdit->text();
					
			}
		}
		catch (UniValue& objError)
		{
			string strError = find_value(objError, "message").get_str();
			QMessageBox::critical(this, windowTitle(),
			tr("Error creating new Cert: \"%1\"").arg(QString::fromStdString(strError)),
				QMessageBox::Ok, QMessageBox::Ok);
			break;
		}
		catch(std::exception& e)
		{
			QMessageBox::critical(this, windowTitle(),
				tr("General exception creating new Cert"),
				QMessageBox::Ok, QMessageBox::Ok);
			break;
		}							

        break;
    case EditCert:
        if(mapper->submit())
        {
			strMethod = string("certupdate");
			params.push_back(ui->certEdit->text().toStdString());
			params.push_back(ui->aliasEdit->currentText().toStdString());
			params.push_back(ui->nameEdit->text().toStdString());
			params.push_back(ui->certDataEdit->toPlainText().toStdString());
			params.push_back(ui->privateBox->currentText() == QString("Yes")? "1": "0");
			params.push_back(ui->safeSearchEdit->currentText().toStdString());
			if(ui->categoryEdit->currentIndex() >= 0)
				params.push_back(ui->categoryEdit->itemData(ui->categoryEdit->currentIndex(), Qt::UserRole).toString().toStdString());
			else
				params.push_back(ui->categoryEdit->currentText().toStdString());
			try {
				UniValue result = tableRPC.execute(strMethod, params);
				if (result.type() != UniValue::VNULL)
				{
					cert = ui->nameEdit->text() + ui->certEdit->text();

				}
			}
			catch (UniValue& objError)
			{
				string strError = find_value(objError, "message").get_str();
				QMessageBox::critical(this, windowTitle(),
				tr("Error updating Cert: \"%1\"").arg(QString::fromStdString(strError)),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}
			catch(std::exception& e)
			{
				QMessageBox::critical(this, windowTitle(),
					tr("General exception updating Cert"),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}	
        }
        break;
    case TransferCert:
        if(mapper->submit())
        {
			strMethod = string("certtransfer");
			params.push_back(ui->certEdit->text().toStdString());
			params.push_back(ui->transferEdit->text().toStdString());
			try {
				UniValue result = tableRPC.execute(strMethod, params);
				if (result.type() != UniValue::VNULL)
				{
					cert = ui->certEdit->text()+ui->transferEdit->text();

				}
			}
			catch (UniValue& objError)
			{
				string strError = find_value(objError, "message").get_str();
				QMessageBox::critical(this, windowTitle(),
                tr("Error transferring Cert: \"%1\"").arg(QString::fromStdString(strError)),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}
			catch(std::exception& e)
			{
				QMessageBox::critical(this, windowTitle(),
                    tr("General exception transferring Cert"),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}	
        }
        break;
    }
    return !cert.isEmpty();
}

void EditCertDialog::accept()
{
    if(!model) return;

    if(!saveCurrentRow())
    {
        switch(model->getEditStatus())
        {
        case CertTableModel::OK:
            // Failed with unknown reason. Just reject.
            break;
        case CertTableModel::NO_CHANGES:
            // No changes were made during edit operation. Just reject.
            break;
        case CertTableModel::INVALID_CERT:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered cert \"%1\" is not a valid Syscoin Cert.").arg(ui->certEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case CertTableModel::DUPLICATE_CERT:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered cert \"%1\" is already taken.").arg(ui->certEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case CertTableModel::WALLET_UNLOCK_FAILURE:
            QMessageBox::critical(this, windowTitle(),
                tr("Could not unlock wallet."),
                QMessageBox::Ok, QMessageBox::Ok);
            break;

        }
        return;
    }
    QDialog::accept();
}

QString EditCertDialog::getCert() const
{
    return cert;
}

void EditCertDialog::setCert(const QString &cert)
{
    this->cert = cert;
    ui->certEdit->setText(cert);
}

#include "editofferdialog.h"
#include "ui_editofferdialog.h"

#include "offertablemodel.h"
#include "guiutil.h"
#include "walletmodel.h"
#include "syscoingui.h"
#include "ui_interface.h"
#include <QDataWidgetMapper>
#include <QMessageBox>
#include <QStringList>
#include "rpcserver.h"
#include "main.h"
#include "qcomboboxdelegate.h"
#include <QSettings>
#include <QStandardItemModel>
#include <boost/algorithm/string.hpp>
using namespace std;

extern const CRPCTable tableRPC;
string getCurrencyToSYSFromAlias(const vector<unsigned char> &vchAliasPeg, const vector<unsigned char> &vchCurrency, CAmount &nFee, const unsigned int &nHeightToFind, vector<string>& rateList, int &precision);
extern bool getCategoryList(vector<string>& categoryList);
extern vector<unsigned char> vchFromString(const std::string &str);
EditOfferDialog::EditOfferDialog(Mode mode, const QString &strCert, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EditOfferDialog), mapper(0), mode(mode), model(0)
{
    ui->setupUi(this);

	ui->aliasPegDisclaimer->setText(tr("<font color='blue'>Choose an alias which has peg information to allow exchange of currencies into SYS amounts based on the pegged values. Consumers will pay amounts based on this peg, the alias must be managed effectively or you may end up selling your offers for unexpected amounts.</font>"));
	ui->privateDisclaimer->setText(tr("<font color='blue'>All offers are first listed as private. If you would like your offer to be public, please edit it after it is created.</font>"));
	ui->offerLabel->setVisible(true);
	ui->offerEdit->setVisible(true);
	ui->offerEdit->setEnabled(false);
	ui->aliasEdit->setEnabled(true);
	ui->currencyDisclaimer->setVisible(true);
	ui->privateEdit->setEnabled(true);
	ui->privateEdit->clear();
	ui->privateEdit->addItem(QString("Yes"));
	ui->privateEdit->addItem(QString("No"));
	ui->currencyEdit->addItem(QString("USD"));
	ui->acceptBTCOnlyEdit->clear();
	ui->acceptBTCOnlyEdit->addItem(QString("No"));
	ui->acceptBTCOnlyEdit->addItem(QString("Yes"));
	ui->btcOnlyDisclaimer->setText(tr("<font color='blue'>You will receive payment in Bitcoin if you have selected <b>Yes</b> to this option and <b>BTC</b> as the currency for the offer.</font>"));
	cert = strCert;
	ui->certEdit->clear();
	ui->certEdit->addItem(tr("Select Certificate (optional)"));
	connect(ui->certEdit, SIGNAL(currentIndexChanged(int)), this, SLOT(certChanged(int)));
	loadAliases();
	connect(ui->aliasEdit,SIGNAL(currentIndexChanged(const QString&)),this,SLOT(aliasChanged(const QString&)));
	loadCerts();
	loadCategories();
	ui->descriptionEdit->setStyleSheet("color: rgb(0, 0, 0); background-color: rgb(255, 255, 255)");
    QSettings settings;
	QString defaultPegAlias, defaultOfferAlias;
	int aliasIndex;
	switch(mode)
    {
    case NewOffer:
		ui->offerLabel->setVisible(false);
		ui->offerEdit->setVisible(false);
		defaultPegAlias = settings.value("defaultPegAlias", "").toString();
		ui->aliasPegEdit->setText(defaultPegAlias);
		defaultOfferAlias = settings.value("defaultOfferAlias", "").toString();
		aliasIndex = ui->aliasEdit->findText(defaultOfferAlias);
		if(aliasIndex >= 0)
			ui->aliasEdit->setCurrentIndex(aliasIndex);
		on_aliasPegEdit_editingFinished();
		ui->privateEdit->setCurrentIndex(ui->privateEdit->findText("Yes"));
		ui->privateEdit->setEnabled(false);
        setWindowTitle(tr("New Offer"));
		ui->currencyDisclaimer->setText(tr("<font color='blue'>You will receive payment in Syscoin equivalent to the Market-value of the currency you have selected.</font>"));
        break;
    case EditOffer:
		ui->currencyEdit->setEnabled(false);
		ui->currencyDisclaimer->setVisible(false);
		
        setWindowTitle(tr("Edit Offer"));
        break;
    case NewCertOffer:
		ui->aliasEdit->setEnabled(false);
		ui->offerLabel->setVisible(false);
		ui->aliasPegEdit->setText(tr("SYS_RATES"));
		on_aliasPegEdit_editingFinished();
		ui->privateEdit->setCurrentIndex(ui->privateEdit->findText("Yes"));
		ui->privateEdit->setEnabled(false);
		ui->offerEdit->setVisible(false);
        setWindowTitle(tr("New Offer(Certificate)"));
		ui->qtyEdit->setText("1");
		ui->qtyEdit->setEnabled(false);
		
		ui->currencyDisclaimer->setText(tr("<font color='blue'>You will receive payment in Syscoin equivalent to the Market-value of the currency you have selected.</font>"));
        break;
	}
	aliasChanged(ui->aliasEdit->currentText());
    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
}
void EditOfferDialog::on_aliasPegEdit_editingFinished()
{
	CAmount nFee;
	vector<string> rateList;
	int precision;
	if(getCurrencyToSYSFromAlias(vchFromString(ui->aliasPegEdit->text().toStdString()), vchFromString(ui->currencyEdit->currentText().toStdString()), nFee, chainActive.Tip()->nHeight, rateList, precision) == "1")
	{
		QMessageBox::warning(this, windowTitle(),
			tr("Warning: %1 alias not found. No currency information available for %2!").arg(ui->aliasPegEdit->text()).arg(ui->currencyEdit->currentText()),
				QMessageBox::Ok, QMessageBox::Ok);
		return;
	}
	ui->currencyEdit->clear();
	for(int i =0;i<rateList.size();i++)
	{
		ui->currencyEdit->addItem(QString::fromStdString(rateList[i]));
	}

}
void EditOfferDialog::setOfferNotSafeBecauseOfAlias(const QString &alias)
{
	ui->safeSearchEdit->setCurrentIndex(ui->safeSearchEdit->findText("No"));
	ui->safeSearchEdit->setEnabled(false);
	ui->safeSearchDisclaimer->setText(tr("<font color='red'><b>%1</b> is not safe to search so this setting can only be set to No").arg(alias));
}
void EditOfferDialog::resetSafeSearch()
{
	ui->safeSearchEdit->setEnabled(true);
	ui->safeSearchDisclaimer->setText(tr("<font color='blue'>Is this offer safe to search? Anything that can be considered offensive to someone should be set to <b>No</b> here. If you do create an offer that is offensive and do not set this option to <b>No</b> your offer will be banned aswell as possibly your store alias!</font>"));
	
}
void EditOfferDialog::aliasChanged(const QString& alias)
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
				setOfferNotSafeBecauseOfAlias(QString::fromStdString(name_str));
			}
			else
				resetSafeSearch();

			if(expired != 0)
			{
				ui->aliasDisclaimer->setText(tr("<font color='red'>This alias has expired, please choose another one</font>"));					
			}
			else
				ui->aliasDisclaimer->setText(tr("<font color='blue'>Select an alias to own this offer</font>"));	
		}
		else
		{
			resetSafeSearch();
			ui->aliasDisclaimer->setText(tr("<font color='blue'>Select an alias to own this offer</font>"));	
		}
	}
	catch (UniValue& objError)
	{
		resetSafeSearch();
		ui->aliasDisclaimer->setText(tr("<font color='blue'>Select an alias to own this offer</font>"));	
	}
	catch(std::exception& e)
	{
		resetSafeSearch();
		ui->aliasDisclaimer->setText(tr("<font color='blue'>Select an alias to own this offer</font>"));	
	}  
}
void EditOfferDialog::certChanged(int index)
{
	if(index > 0)
	{
		ui->qtyEdit->setText("1");
		ui->qtyEdit->setEnabled(false);
		ui->aliasEdit->setEnabled(false);
		ui->aliasDisclaimer->setText(tr("<font color='blue'>This will automatically use the alias which owns the certificate you are selling</font>"));
	}
	else if(index == 0)
	{
		ui->aliasDisclaimer->setText(tr("<font color='blue'>Select an alias to own this offer</font>"));
		ui->aliasEdit->setEnabled(true);
		ui->qtyEdit->setEnabled(true);
	}
}

void EditOfferDialog::addParentItem( QStandardItemModel * model, const QString& text, const QVariant& data )
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

void EditOfferDialog::addChildItem( QStandardItemModel * model, const QString& text, const QVariant& data )
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
void EditOfferDialog::loadCategories()
{
    QStandardItemModel * model = new QStandardItemModel;
	vector<string> categoryList;
	if(!getCategoryList(categoryList))
	{
		return;
	}
	for(unsigned int i = 0;i< categoryList.size(); i++)
	{
		vector<string> categories;
		boost::split(categories,categoryList[i],boost::is_any_of(">"));
		if(categories.size() > 0)
		{
			for(unsigned int j = 0;j< categories.size(); j++)
			{
				boost::algorithm::trim(categories[j]);
				// only support 2 levels in qt GUI for categories
				if(j == 0)
				{
					addParentItem(model, QString::fromStdString(categories[0]), QVariant(QString::fromStdString(categories[0])));
				}
				else if(j == 1)
				{
					addChildItem(model, QString::fromStdString(categories[1]), QVariant(QString::fromStdString(categoryList[i])));
				}
			}
		}
		else
		{
			addParentItem(model, QString::fromStdString(categoryList[i]), QVariant(QString::fromStdString(categoryList[i])));
		}
	}
    ui->categoryEdit->setModel(model);
    ui->categoryEdit->setItemDelegate(new ComboBoxDelegate);
}
void EditOfferDialog::loadCerts()
{
	string strMethod = string("certlist");
    UniValue params(UniValue::VARR); 
	UniValue result;
	string name_str;
	string title_str;
	string alias_str;
	int expired = 0;
	
	try {
		result = tableRPC.execute(strMethod, params);

		if (result.type() == UniValue::VARR)
		{
			name_str = "";
			title_str = "";
			alias_str = "";
			expired = 0;


	
			const UniValue &arr = result.get_array();
		    for (unsigned int idx = 0; idx < arr.size(); idx++) {
			    const UniValue& input = arr[idx];
				if (input.type() != UniValue::VOBJ)
					continue;
				const UniValue& o = input.get_obj();
				name_str = "";

				expired = 0;


		
				const UniValue& name_value = find_value(o, "cert");
				if (name_value.type() == UniValue::VSTR)
					name_str = name_value.get_str();
				const UniValue& title_value = find_value(o, "title");
				if (title_value.type() == UniValue::VSTR)
					title_str = title_value.get_str();	
				const UniValue& alias_value = find_value(o, "alias");
				if (alias_value.type() == UniValue::VSTR)
					alias_str = alias_value.get_str();	
				const UniValue& expired_value = find_value(o, "expired");
				if (expired_value.type() == UniValue::VNUM)
					expired = expired_value.get_int();
				
				if(expired == 0)
				{
					QString name = QString::fromStdString(name_str);
					QString title = QString::fromStdString(title_str);
					QString alias = QString::fromStdString(alias_str);
					QString certText = name + " - " + title;
					ui->certEdit->addItem(certText,name);
					if(name == cert)
					{
						int index = ui->certEdit->findData(name);
						if ( index != -1 ) 
						{
						    ui->certEdit->setCurrentIndex(index);
							ui->aliasEdit->setEnabled(false);
							ui->aliasDisclaimer->setText(tr("<font color='blue'>This will automatically use the alias which owns the certificate you are selling</font>"));
						}
						index = ui->aliasEdit->findData(alias);
						if ( index != -1 ) 
						{
						    ui->aliasEdit->setCurrentIndex(index);
							ui->aliasEdit->setEnabled(false);
							ui->aliasDisclaimer->setText(tr("<font color='blue'>This will automatically use the alias which owns the certificate you are selling</font>"));
						}
					}
				}
				
			}
		}
	}
	catch (UniValue& objError)
	{
		string strError = find_value(objError, "message").get_str();
		QMessageBox::critical(this, windowTitle(),
			tr("Could not refresh cert list: %1").arg(QString::fromStdString(strError)),
				QMessageBox::Ok, QMessageBox::Ok);
	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
			tr("There was an exception trying to refresh the cert list: ") + QString::fromStdString(e.what()),
				QMessageBox::Ok, QMessageBox::Ok);
	}         
 
}
void EditOfferDialog::loadAliases()
{
	ui->aliasEdit->clear();
	string strMethod = string("aliaslist");
    UniValue params(UniValue::VARR); 
	UniValue result ;
	string name_str;
	int expired = 0;
	bool safeSearch;
	int safetyLevel;
	try {
		result = tableRPC.execute(strMethod, params);

		if (result.type() == UniValue::VARR)
		{
			name_str = "";
			safeSearch = false;
			expired = safetyLevel = 0;


	
			const UniValue &arr = result.get_array();
		    for (unsigned int idx = 0; idx < arr.size(); idx++) {
			    const UniValue& input = arr[idx];
				if (input.type() != UniValue::VOBJ)
					continue;
				const UniValue& o = input.get_obj();
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
					setOfferNotSafeBecauseOfAlias(QString::fromStdString(name_str));
				}				
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
EditOfferDialog::~EditOfferDialog()
{
    delete ui;
}

void EditOfferDialog::setModel(WalletModel* walletModel, OfferTableModel *model)
{
    this->model = model;
	this->walletModel = walletModel;
    if(!model) return;

    mapper->setModel(model);
	mapper->addMapping(ui->offerEdit, OfferTableModel::Name);
	mapper->addMapping(ui->certEdit, OfferTableModel::Cert);
    mapper->addMapping(ui->nameEdit, OfferTableModel::Title);
    mapper->addMapping(ui->priceEdit, OfferTableModel::Price);
	mapper->addMapping(ui->qtyEdit, OfferTableModel::Qty);	
	mapper->addMapping(ui->descriptionEdit, OfferTableModel::Description);		
	mapper->addMapping(ui->aliasPegEdit, OfferTableModel::AliasPeg);	
	mapper->addMapping(ui->geoLocationEdit, OfferTableModel::GeoLocation);
    mapper->addMapping(ui->categoryEdit, OfferTableModel::Category);
}

void EditOfferDialog::loadRow(int row)
{
	const QModelIndex tmpIndex;
	if(model)
	{
		mapper->setCurrentIndex(row);
		QModelIndex indexCurrency = model->index(row, OfferTableModel::Currency, tmpIndex);
		QModelIndex indexPrivate = model->index(row, OfferTableModel::Private, tmpIndex);	
		QModelIndex indexAlias = model->index(row, OfferTableModel::Alias, tmpIndex);
		QModelIndex indexQty = model->index(row, OfferTableModel::Qty, tmpIndex);
		QModelIndex indexBTCOnly = model->index(row, OfferTableModel::AcceptBTCOnly, tmpIndex);
		QModelIndex indexSafeSearch = model->index(row, OfferTableModel::SafeSearch, tmpIndex);
		QModelIndex indexCategory = model->index(row, OfferTableModel::Category, tmpIndex);
		if(indexPrivate.isValid())
		{
			QString privateStr = indexPrivate.data(OfferTableModel::PrivateRole).toString();
			ui->privateEdit->setCurrentIndex(ui->privateEdit->findText(privateStr));
		}
		if(indexCurrency.isValid())
		{
			on_aliasPegEdit_editingFinished();
			QString currencyStr = indexCurrency.data(OfferTableModel::CurrencyRole).toString();
			ui->currencyEdit->setCurrentIndex(ui->currencyEdit->findText(currencyStr));
		}
		if(indexBTCOnly.isValid())
		{
			QString btcOnlyStr = indexBTCOnly.data(OfferTableModel::BTCOnlyRole).toString();
			ui->acceptBTCOnlyEdit->setCurrentIndex(ui->acceptBTCOnlyEdit->findText(btcOnlyStr));
		}
		if(indexSafeSearch.isValid() && ui->safeSearchEdit->isEnabled())
		{
			QString safeSearchStr = indexSafeSearch.data(OfferTableModel::SafeSearchRole).toString();
			ui->safeSearchEdit->setCurrentIndex(ui->safeSearchEdit->findText(safeSearchStr));
		}
		if(indexCategory.isValid())
		{
			QString categoryStr = indexCategory.data(OfferTableModel::CategoryRole).toString();
			int index = ui->categoryEdit->findData(QVariant(categoryStr));
			if ( index != -1 ) 
			{ 
				ui->categoryEdit->setCurrentIndex(index);
			}
		}
		if(indexAlias.isValid())
		{
			QString aliasStr = indexAlias.data(OfferTableModel::AliasRole).toString();
			ui->aliasEdit->setCurrentIndex(ui->aliasEdit->findText(aliasStr));
		}
		if(indexQty.isValid())
		{
			QString qtyStr = indexBTCOnly.data(OfferTableModel::QtyRole).toString();
			if(qtyStr == tr("unlimited"))
				ui->qtyEdit->setText("-1");
			else
				ui->qtyEdit->setText(qtyStr);
		}
	}
}

bool EditOfferDialog::saveCurrentRow()
{

    if(!walletModel) return false;
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if(!ctx.isValid())
    {
		if(model)
			model->editStatus = OfferTableModel::WALLET_UNLOCK_FAILURE;
        return false;
    }
	QString defaultPegAlias;
	QSettings settings;
	UniValue params(UniValue::VARR);
	string strMethod;
    switch(mode)
    {
    case NewOffer:
	case NewCertOffer:
        if (ui->nameEdit->text().trimmed().isEmpty()) {
            ui->nameEdit->setText("");
            QMessageBox::information(this, windowTitle(),
            tr("Empty name for Offer not allowed. Please try again"),
                QMessageBox::Ok, QMessageBox::Ok);
            return false;
        }
		defaultPegAlias = settings.value("defaultPegAlias", "").toString();
		 if (ui->aliasPegEdit->text() != defaultPegAlias) {
			QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm Alias Peg"),
                 tr("Warning: By default the system peg is <b>%1</b>.") + "<br><br>" + tr("Are you sure you wish to choose this alias as your offer peg?").arg(defaultPegAlias),
                 QMessageBox::Yes|QMessageBox::Cancel,
                 QMessageBox::Cancel);
			if(retval == QMessageBox::Cancel)
				return false;
		}
		strMethod = string("offernew");
		params.push_back(ui->aliasPegEdit->text().toStdString());
		params.push_back(ui->aliasEdit->currentText().toStdString());
		if(ui->categoryEdit->currentIndex() >= 0)
			params.push_back(ui->categoryEdit->itemData(ui->categoryEdit->currentIndex(), Qt::UserRole).toString().toStdString());
		else
			params.push_back(ui->categoryEdit->currentText().toStdString());
		params.push_back(ui->nameEdit->text().toStdString());
		params.push_back(ui->qtyEdit->text().toStdString());
		params.push_back(ui->priceEdit->text().toStdString());
		params.push_back(ui->descriptionEdit->toPlainText().toStdString());
		params.push_back(ui->currencyEdit->currentText().toStdString());
		if(ui->certEdit->currentIndex() >= 0)
		{
			if(!ui->categoryEdit->currentText().startsWith("certificate"))
			{
				QMessageBox::critical(this, windowTitle(),
				tr("Error creating new Offer: Certificate offers must use a certificate category"),
					QMessageBox::Ok, QMessageBox::Ok);
				return false;
			}
			params.push_back(ui->certEdit->itemData(ui->certEdit->currentIndex()).toString().toStdString());
		}
		else
		{
			if(ui->categoryEdit->currentText().startsWith("certificate"))
			{
				QMessageBox::critical(this, windowTitle(),
				tr("Error creating new Offer: offer not selling a certificate yet used certificate as a category"),
					QMessageBox::Ok, QMessageBox::Ok);
				return false;
			}
			params.push_back("nocert");
		}
		params.push_back("1");
		params.push_back(ui->acceptBTCOnlyEdit->currentText() == QString("Yes")? "1": "0");
		params.push_back(ui->geoLocationEdit->text().toStdString());
		params.push_back(ui->safeSearchEdit->currentText().toStdString());
		try {
            UniValue result = tableRPC.execute(strMethod, params);
			const UniValue &arr = result.get_array();
			string strResult = arr[0].get_str();
			offer = ui->nameEdit->text();
			
		}
		catch (UniValue& objError)
		{
			string strError = find_value(objError, "message").get_str();
			QMessageBox::critical(this, windowTitle(),
			tr("Error creating new Offer: \"%1\"").arg(QString::fromStdString(strError)),
				QMessageBox::Ok, QMessageBox::Ok);
			break;
		}
		catch(std::exception& e)
		{
			QMessageBox::critical(this, windowTitle(),
				tr("General exception creating new Offer: \"%1\"").arg(QString::fromStdString(e.what())),
				QMessageBox::Ok, QMessageBox::Ok);
			break;
		}							

        break;
    case EditOffer:
		defaultPegAlias = settings.value("defaultPegAlias", "").toString();
		 if (ui->aliasPegEdit->text() != defaultPegAlias) {
			QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm Alias Peg"),
                 tr("Warning: By default the system peg is <b>%1</b>.") + "<br><br>" + tr("Are you sure you wish to choose this alias as your offer peg?").arg(defaultPegAlias),
                 QMessageBox::Yes|QMessageBox::Cancel,
                 QMessageBox::Cancel);
			if(retval == QMessageBox::Cancel)
				return false;
		}
        if(mapper->submit())
        {
			strMethod = string("offerupdate");
			params.push_back(ui->aliasPegEdit->text().toStdString());
			params.push_back(ui->aliasEdit->currentText().toStdString());
			params.push_back(ui->offerEdit->text().toStdString());
			if(ui->categoryEdit->currentIndex() >= 0)
				params.push_back(ui->categoryEdit->itemData(ui->categoryEdit->currentIndex(), Qt::UserRole).toString().toStdString());
			else
				params.push_back(ui->categoryEdit->currentText().toStdString());
			params.push_back(ui->nameEdit->text().toStdString());
			params.push_back(ui->qtyEdit->text().toStdString());
			params.push_back(ui->priceEdit->text().toStdString());
			params.push_back(ui->descriptionEdit->toPlainText().toStdString());
			params.push_back(ui->privateEdit->currentText() == QString("Yes")? "1": "0");
			if(ui->certEdit->currentIndex() >= 0)
			{
				if(!ui->categoryEdit->currentText().startsWith("certificate"))
				{
					QMessageBox::critical(this, windowTitle(),
					tr("Error updating Offer: Certificate offers must use a certificate category"),
						QMessageBox::Ok, QMessageBox::Ok);
					return false;
				}
				params.push_back(ui->certEdit->itemData(ui->certEdit->currentIndex()).toString().toStdString());
			}
			else
			{
				if(ui->categoryEdit->currentText().startsWith("certificate"))
				{
					QMessageBox::critical(this, windowTitle(),
					tr("Error updating Offer: offer not selling a certificate yet used certificate as a category"),
						QMessageBox::Ok, QMessageBox::Ok);
					return false;
				}
				params.push_back("nocert");
			}

			params.push_back("");
			params.push_back(ui->geoLocationEdit->text().toStdString());
			params.push_back(ui->safeSearchEdit->currentText().toStdString());


			try {
				UniValue result = tableRPC.execute(strMethod, params);
				if (result.type() != UniValue::VNULL)
				{
					offer = ui->nameEdit->text() + ui->offerEdit->text();

				}
			}
			catch (UniValue& objError)
			{
				string strError = find_value(objError, "message").get_str();
				QMessageBox::critical(this, windowTitle(),
				tr("Error updating Offer: \"%1\"").arg(QString::fromStdString(strError)),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}
			catch(std::exception& e)
			{
				QMessageBox::critical(this, windowTitle(),
					tr("General exception updating Offer: \"%1\"").arg(QString::fromStdString(e.what())),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}	
        }
        break;
    }
    return !offer.isEmpty();
}
void EditOfferDialog::on_cancelButton_clicked()
{
    reject();
}
void EditOfferDialog::on_okButton_clicked()
{
    mapper->submit();
    accept();
}
void EditOfferDialog::accept()
{
    if(!saveCurrentRow())
    {
		if(model)
		{
			switch(model->getEditStatus())
			{
			case OfferTableModel::OK:
				// Failed with unknown reason. Just reject.
				break;
			case OfferTableModel::NO_CHANGES:
				// No changes were made during edit operation. Just reject.
				break;
			case OfferTableModel::INVALID_OFFER:
				QMessageBox::warning(this, windowTitle(),
					tr("The entered offer \"%1\" is not a valid Syscoin Offer.").arg(ui->offerEdit->text()),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			case OfferTableModel::DUPLICATE_OFFER:
				QMessageBox::warning(this, windowTitle(),
					tr("The entered offer \"%1\" is already taken.").arg(ui->offerEdit->text()),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			case OfferTableModel::WALLET_UNLOCK_FAILURE:
				QMessageBox::critical(this, windowTitle(),
					tr("Could not unlock wallet."),
					QMessageBox::Ok, QMessageBox::Ok);
				break;

			}
			return;
		}
    }
    QDialog::accept();
}

QString EditOfferDialog::getOffer() const
{
    return offer;
}

void EditOfferDialog::setOffer(const QString &offer)
{
    this->offer = offer;
    ui->offerEdit->setText(offer);
}

#include "acceptandpayofferlistpage.h"
#include "ui_acceptandpayofferlistpage.h"
#include "init.h"
#include "util.h"


#include "offertablemodel.h"
#include "offer.h"

#include "bitcoingui.h"
#include "bitcoinrpc.h"

#include "guiutil.h"

#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QMenu>
#include <QString>
#include <QUrl>
using namespace std;
using namespace json_spirit;
extern const CRPCTable tableRPC;
extern string JSONRPCReply(const Value& result, const Value& error, const Value& id);

AcceptandPayOfferListPage::AcceptandPayOfferListPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AcceptandPayOfferListPage)
{
    ui->setupUi(this);


    ui->labelExplanation->setText(tr("Accept and purchase this offer, SysCoins will be used to complete the transaction."));
    connect(ui->pushButton, SIGNAL(clicked()), this, SLOT(acceptandpay()));
}

AcceptandPayOfferListPage::~AcceptandPayOfferListPage()
{
    delete ui;
}
// send offeraccept with offer guid/qty as params and then send offerpay with wtxid (first param of response) as param, using RPC commands.
void AcceptandPayOfferListPage::acceptandpay()
{

		Array params;
		Value valError;
		Object ret ;
		Value valResult;
		Array arr;
		Value valId;
		Value result ;
		string strReply;
		string strError;
		string strMethod = string("offeraccept");
		 
		params.push_back(ui->offeridEdit->text().toStdString());
		params.push_back(ui->qtyEdit->text().toStdString());

	    try {
            result = tableRPC.execute(strMethod, params);
		}
		catch (Object& objError)
		{
			strError = find_value(objError, "message").get_str();
			QMessageBox::critical(this, windowTitle(),
			tr("Error accepting offer: \"%1\"").arg(QString::fromStdString(strError)),
				QMessageBox::Ok, QMessageBox::Ok);
			return;
		}
		catch(std::exception& e)
		{
			QMessageBox::critical(this, windowTitle(),
				tr("General exception when accepting offer"),
				QMessageBox::Ok, QMessageBox::Ok);
			return;
		}
	
		if (result.type() == array_type)
		{
			arr = result.get_array();
			strMethod = string("offerpay");
			params.clear();
			params.push_back(arr[0].get_str());

		    try {
                result = tableRPC.execute(strMethod, params);
			}
			catch (Object& objError)
			{
				strError = find_value(objError, "message").get_str();
				QMessageBox::critical(this, windowTitle(),
				tr("Error paying for offer: \"%1\"").arg(QString::fromStdString(strError)),
					QMessageBox::Ok, QMessageBox::Ok);
				return;
			}
			catch(std::exception& e)
			{
				QMessageBox::critical(this, windowTitle(),
					tr("General exception when trying to pay for offer"),
					QMessageBox::Ok, QMessageBox::Ok);
						return;
			}
			
		}
		else
		{
			QMessageBox::critical(this, windowTitle(),
				tr("Error: Invalid response from offeraccept command"),
				QMessageBox::Ok, QMessageBox::Ok);
			return;
		}

		QMessageBox::information(this, windowTitle(),
			tr("Offer transaction completed successfully!"),
				QMessageBox::Ok, QMessageBox::Ok);	

   

}
bool AcceptandPayOfferListPage::handleURI(const QUrl &uri, COffer* offerOut)
{
	  // return if URI is not valid or is no bitcoin URI
    if(!uri.isValid() || uri.scheme() != QString("syscoin"))
        return false;

    COffer rv;
	rv.nQty = 0;
	string strError;
	string strMethod = string("offerinfo");
	Array params;
	Value result;
	params.push_back(uri.path().toStdString());

    try {
        result = tableRPC.execute(strMethod, params);

		if (result.type() == null_type)
		{
			Object offerObj;
			offerObj = result.get_obj();

			rv.vchRand = vchFromString(find_value(offerObj, "id").get_str());
			rv.sTitle = vchFromString(find_value(offerObj, "title").get_str());
			rv.sCategory = vchFromString(find_value(offerObj, "category").get_str());
			rv.nPrice = find_value(offerObj, "price").get_uint64();
			rv.nQty = find_value(offerObj, "quantity").get_int64();
			rv.sDescription = vchFromString(find_value(offerObj, "description").get_str());
			rv.nFee = find_value(offerObj, "fee").get_uint64();
			rv.vchPaymentAddress = vchFromString(find_value(offerObj, "payment_address").get_str());
			if(rv.nQty <= 0)
			{
				return false;
			}
		}
		 

	#if QT_VERSION < 0x050000
		QList<QPair<QString, QString> > items = uri.queryItems();
	#else
		QUrlQuery uriQuery(uri);
		QList<QPair<QString, QString> > items = uriQuery.queryItems();
	#endif
		for (QList<QPair<QString, QString> >::iterator i = items.begin(); i != items.end(); i++)
		{
			bool fShouldReturnFalse = true;
			if (i->first == "quantity")
			{
				int64 qty = i->second.toLong();
				if(rv.nQty < qty)
				{
					return false;
				}
				else
				{
					rv.nQty = qty;
				}
				fShouldReturnFalse = false;
			}
			if (fShouldReturnFalse)
				return false;
		}
		if(offerOut)
		{
			*offerOut = rv;
		}
	}
	catch (Object& objError)
	{
		return false;
	}
	catch(std::exception& e)
	{
		return false;
	}

    return true;
}
void AcceptandPayOfferListPage::setValue(const COffer &offer)
{
    ui->offeridEdit->setText(QString::fromStdString(stringFromVch(offer.vchRand)));
    ui->qtyEdit->setText(QString::number(offer.nQty));
}

bool AcceptandPayOfferListPage::handleURI(const QString& strURI, COffer* offerOut)
{
	QString URI = strURI;
	if(URI.startsWith("syscoin://"))
    {
        URI.replace(0, 11, "syscoin:");
    }
    QUrl uriInstance(URI);
    return handleURI(uriInstance, offerOut);
}


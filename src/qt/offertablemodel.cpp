#include "offertablemodel.h"

#include "guiutil.h"
#include "walletmodel.h"

#include "wallet.h"
#include "base58.h"

#include <QFont>

using namespace std;

const QString OfferTableModel::Offer = "O";
const QString OfferTableModel::OfferAccept = "A";

class COfferDB;

extern COfferDB *pofferdb;

int GetOfferExpirationDepth(int nHeight);

struct OfferTableEntry
{
    enum Type {
        Offer,
        OfferAccept
    };

    Type type;
    QString title;
    QString offer;
    QString category;
    QString price;
    QString quantity;
    QString expirationdepth;
	QString description;
    OfferTableEntry() {}
    OfferTableEntry(Type type, const QString &title, const QString &offer, const QString &category, const QString &price, const QString &quantity, const QString &expirationdepth, const QString &description):
        type(type), title(title), offer(offer), category(category), price(price), quantity(quantity), expirationdepth(expirationdepth), description(description) {}
};

struct OfferTableEntryLessThan
{
    bool operator()(const OfferTableEntry &a, const OfferTableEntry &b) const
    {
        return a.offer < b.offer;
    }
    bool operator()(const OfferTableEntry &a, const QString &b) const
    {
        return a.offer < b;
    }
    bool operator()(const QString &a, const OfferTableEntry &b) const
    {
        return a < b.offer;
    }
};

#define NAMEMAPTYPE map<vector<unsigned char>, uint256>

// Private implementation
class OfferTablePriv
{
public:
    CWallet *wallet;
    QList<OfferTableEntry> cachedOfferTable;
    OfferTableModel *parent;

    OfferTablePriv(CWallet *wallet, OfferTableModel *parent):
        wallet(wallet), parent(parent) {}

		void refreshOfferTable(OfferModelType type)
    {

        cachedOfferTable.clear();
        {
			
            CBlockIndex* pindex = pindexGenesisBlock;
            LOCK(wallet->cs_wallet);
            while (pindex) {
                int nHeight = pindex->nHeight;
                CBlock block;
                block.ReadFromDisk(pindex);
                uint256 txblkhash;

                BOOST_FOREACH(CTransaction& tx, block.vtx) {

                    if (tx.nVersion != SYSCOIN_TX_VERSION)
                        continue;

                    int op, nOut;
                    vector<vector<unsigned char> > vvchArgs;
                    bool o = DecodeOfferTx(tx, op, nOut, vvchArgs, nHeight);
					if (!o || !IsOfferOp(op) || (!IsOfferMine(tx) && type != AllOffers)) continue;

                    // get the transaction
                    if(!GetTransaction(tx.GetHash(), tx, txblkhash, true))
                        continue;

                    // attempt to read offer from txn
                    COffer theOffer;
                    COfferAccept theOfferAccept;
                    if(!theOffer.UnserializeFromTx(tx))
                        continue;

                    vector<COffer> vtxPos;
                    if(!pofferdb->ReadOffer(theOffer.vchRand, vtxPos))
                        continue;

                    int nExpHeight = vtxPos.back().nHeight + GetOfferExpirationDepth(vtxPos.back().nHeight);

                    double nPrice = theOffer.nPrice / COIN;
                    int nQty = theOffer.nQty;

                    if(theOffer.accepts.size()) {
                        theOfferAccept = theOffer.accepts.back();
                        nPrice = theOfferAccept.nPrice / COIN;
                        nQty = theOfferAccept.nQty;
                        nExpHeight = 0;
                    }

                    if(op == OP_OFFER_ACTIVATE)
                        cachedOfferTable.append(OfferTableEntry(theOffer.accepts.size() ? OfferTableEntry::OfferAccept : OfferTableEntry::Offer,
                                          QString::fromStdString(stringFromVch(theOffer.sTitle)),
                                          QString::fromStdString(stringFromVch(theOffer.vchRand)),
                                          QString::fromStdString(stringFromVch(theOffer.sCategory)),
                                          QString::fromStdString(strprintf("%lf", nPrice)),
                                          QString::fromStdString(strprintf("%d", nQty)),
                                          QString::fromStdString(strprintf("%d", nExpHeight)),
										  QString::fromStdString(stringFromVch(theOffer.sDescription))));
                }
				if(size() > 500 && type == AllOffers)
					break;
                pindex = pindex->pnext;
            }
        }
        
        // qLowerBound() and qUpperBound() require our cachedCertIssuerTable list to be sorted in asc order
        qSort(cachedOfferTable.begin(), cachedOfferTable.end(), OfferTableEntryLessThan());
    }

    void updateEntry(const QString &offer, const QString &title, const QString &category,
		const QString &price, const QString &quantity, const QString &expdepth, const QString &description, OfferModelType type, int status)
    {
		if(!parent || parent->modelType != type)
		{
			return;
		}
        // Find offer / value in model
        QList<OfferTableEntry>::iterator lower = qLowerBound(
            cachedOfferTable.begin(), cachedOfferTable.end(), offer, OfferTableEntryLessThan());
        QList<OfferTableEntry>::iterator upper = qUpperBound(
            cachedOfferTable.begin(), cachedOfferTable.end(), offer, OfferTableEntryLessThan());
        int lowerIndex = (lower - cachedOfferTable.begin());
        int upperIndex = (upper - cachedOfferTable.begin());
        bool inModel = (lower != upper);
		
        OfferTableEntry::Type newEntryType = /*isAccept ? OfferTableEntry::OfferAccept :*/ OfferTableEntry::Offer;

        switch(status)
        {
        case CT_NEW:
            if(inModel)
            {
                OutputDebugStringF("Warning: OfferTablePriv::updateEntry: Got CT_NOW, but entry is already in model\n");
                break;
            }
            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            cachedOfferTable.insert(lowerIndex, OfferTableEntry(newEntryType, title, offer, category, price, quantity, expdepth, description));
            parent->endInsertRows();
            break;
        case CT_UPDATED:
            if(!inModel)
            {
                OutputDebugStringF("Warning: OfferTablePriv::updateEntry: Got CT_UPDATED, but entry is not in model\n");
                break;
            }
            lower->type = newEntryType;
            lower->title = title;
            lower->category = category;
            lower->price = price;
            lower->quantity = quantity;
            lower->expirationdepth = expdepth;
			lower->description = description;
            parent->emitDataChanged(lowerIndex);
            break;
        case CT_DELETED:
            if(!inModel)
            {
                OutputDebugStringF("Warning: OfferTablePriv::updateEntry: Got CT_DELETED, but entry is not in model\n");
                break;
            }
            parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex-1);
            cachedOfferTable.erase(lower, upper);
            parent->endRemoveRows();
            break;
        }
    }

    int size()
    {
        return cachedOfferTable.size();
    }

    OfferTableEntry *index(int idx)
    {
        if(idx >= 0 && idx < cachedOfferTable.size())
        {
            return &cachedOfferTable[idx];
        }
        else
        {
            return 0;
        }
    }
};

OfferTableModel::OfferTableModel(CWallet *wallet, WalletModel *parent, OfferModelType type) :
    QAbstractTableModel(parent),walletModel(parent),wallet(wallet),priv(0), modelType(type)
{
    columns << tr("Offer") << tr("Category") << tr("Title") << tr("Price") << tr("Quantity") << tr("Expiration Height") << tr("Description");
    priv = new OfferTablePriv(wallet, this);
    priv->refreshOfferTable(type);
}

OfferTableModel::~OfferTableModel()
{
    delete priv;
}

int OfferTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int OfferTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant OfferTableModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();

    OfferTableEntry *rec = static_cast<OfferTableEntry*>(index.internalPointer());

    if(role == Qt::DisplayRole || role == Qt::EditRole)
    {
        switch(index.column())
        {
        case Title:
            return rec->title;
        case Name:
            return rec->offer;
        case Category:
            return rec->category;
        case Price:
            return rec->price;
        case Quantity:
            return rec->quantity;
        case ExpirationDepth:
            return rec->expirationdepth;
        case Description:
            return rec->description;
        }
    }
    else if (role == Qt::FontRole)
    {
        QFont font;
//        if(index.column() == Name)
//        {
//            font = GUIUtil::bitcoinAddressFont();
//        }
        return font;
    }
    else if (role == TypeRole)
    {
        switch(rec->type)
        {
        case OfferTableEntry::Offer:
            return Offer;
        case OfferTableEntry::OfferAccept:
            return OfferAccept;
        default: break;
        }
    }
    return QVariant();
}

bool OfferTableModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if(!index.isValid())
        return false;
    OfferTableEntry *rec = static_cast<OfferTableEntry*>(index.internalPointer());

    editStatus = OK;

    if(role == Qt::EditRole)
    {
        switch(index.column())
        {
        case ExpirationDepth:
            // Do nothing, if old value == new value
            if(rec->expirationdepth == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            break;
        case Quantity:
            // Do nothing, if old value == new value
            if(rec->quantity == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            break;
        case Price:
            // Do nothing, if old value == new value
            if(rec->price == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            break;
        case Category:
            // Do nothing, if old value == new value
            if(rec->category == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            break;
        case Title:
            // Do nothing, if old value == new value
            if(rec->title == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            break;
        case Description:
            // Do nothing, if old value == new value
            if(rec->description == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            break;
        case Name:
            // Do nothing, if old offer == new offer
            if(rec->offer == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            // Refuse to set invalid offer, set error status and return false
            else if(false /* validate offer */)
            {
                editStatus = INVALID_OFFER;
                return false;
            }
            // Check for duplicate offeres to prevent accidental deletion of offeres, if you try
            // to paste an existing offer over another offer (with a different label)
            else if(false /* check duplicates */)
            {
                editStatus = DUPLICATE_OFFER;
                return false;
            }
            // Double-check that we're not overwriting a receiving offer
            else if(rec->type == OfferTableEntry::Offer)
            {
                {
                    // update offer
                }
            }
            break;
        }
        return true;
    }
    return false;
}

QVariant OfferTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal)
    {
        if(role == Qt::DisplayRole)
        {
            return columns[section];
        }
    }
    return QVariant();
}

Qt::ItemFlags OfferTableModel::flags(const QModelIndex &index) const
{
    if(!index.isValid())
        return 0;
    //OfferTableEntry *rec = static_cast<OfferTableEntry*>(index.internalPointer());

    Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    // only value is editable.
    if(index.column()==Title)
    {
        retval |= Qt::ItemIsEditable;
    }
    return retval;
}

QModelIndex OfferTableModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    OfferTableEntry *data = priv->index(row);
    if(data)
    {
        return createIndex(row, column, priv->index(row));
    }
    else
    {
        return QModelIndex();
    }
}

void OfferTableModel::updateEntry(const QString &offer, const QString &title, const QString &category, const QString &price,
								  const QString &quantity, const QString &expdepth, const QString &description, OfferModelType type, int status)
{
    // Update offer book model from Bitcoin core
    priv->updateEntry(offer, title, category, price, quantity, expdepth, description, type, status);
}

QString OfferTableModel::addRow(const QString &type, const QString &title, const QString &offer, const QString &category, 
	const QString &price, const QString &quantity, const QString &expdepth, const QString &description)
{
    std::string strTitle = title.toStdString();
    std::string strOffer = offer.toStdString();
    std::string strCategory = category.toStdString();
    std::string strPrice = price.toStdString();
    std::string strQuantity = quantity.toStdString();
    std::string strExpdepth = expdepth.toStdString();
	std::string strDescription = description.toStdString();
    editStatus = OK;

    if(false /*validate offer*/)
    {
        editStatus = INVALID_OFFER;
        return QString();
    }
    // Check for duplicate offeres
    {
        LOCK(wallet->cs_wallet);
        if(false/* check duplicate offeres */)
        {
            editStatus = DUPLICATE_OFFER;
            return QString();
        }
    }

    // Add entry

    return QString::fromStdString(strOffer);
}

bool OfferTableModel::removeRows(int row, int count, const QModelIndex &parent)
{
    // refuse to remove offeres.
    return false;
}

/* Look up value for offer, if not found return empty string.
 */
QString OfferTableModel::valueForOffer(const QString &offer) const
{
    return QString::fromStdString("{}");
}

int OfferTableModel::lookupOffer(const QString &offer) const
{
    QModelIndexList lst = match(index(0, Name, QModelIndex()),
                                Qt::EditRole, offer, 1, Qt::MatchExactly);
    if(lst.isEmpty())
    {
        return -1;
    }
    else
    {
        return lst.at(0).row();
    }
}

void OfferTableModel::emitDataChanged(int idx)
{
    emit dataChanged(index(idx, 0, QModelIndex()), index(idx, columns.length()-1, QModelIndex()));
}

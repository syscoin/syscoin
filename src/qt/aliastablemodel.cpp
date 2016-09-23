
#include "aliastablemodel.h"

#include "guiutil.h"
#include "walletmodel.h"

#include "wallet/wallet.h"
#include "base58.h"

#include <QFont>
#include "rpcserver.h"
using namespace std;

const QString AliasTableModel::Alias = "A";


extern const CRPCTable tableRPC;
struct AliasTableEntry
{
    enum Type {
        Alias
    };

    Type type;
    QString value;
	QString privvalue;
    QString alias;
	QString expires_on;
	QString expires_in;
	QString expired;
	QString safesearch;
	int buyer_rating;
	int buyer_ratingcount;
	int seller_rating;
	int seller_ratingcount;
	int arbiter_rating;
	int arbiter_ratingcount;
    AliasTableEntry() {}
    AliasTableEntry(Type type, const QString &alias, const QString &value,  const QString &privvalue, const QString &expires_on,const QString &expires_in, const QString &expired,  const QString &safesearch, int buyer_rating, int buyer_ratingcount, int seller_rating, int seller_ratingcount, int arbiter_rating, int arbiter_ratingcount):
        type(type), alias(alias), value(value), privvalue(privvalue), expires_on(expires_on), expires_in(expires_in), expired(expired), safesearch(safesearch), buyer_rating(buyer_rating), buyer_ratingcount(buyer_ratingcount), seller_rating(seller_rating), seller_ratingcount(seller_ratingcount), arbiter_rating(arbiter_rating), arbiter_ratingcount(arbiter_ratingcount) {}
};

struct AliasTableEntryLessThan
{
    bool operator()(const AliasTableEntry &a, const AliasTableEntry &b) const
    {
        return a.alias < b.alias;
    }
    bool operator()(const AliasTableEntry &a, const QString &b) const
    {
        return a.alias < b;
    }
    bool operator()(const QString &a, const AliasTableEntry &b) const
    {
        return a < b.alias;
    }
};

// Private implementation
class AliasTablePriv
{
public:
    CWallet *wallet;
    QList<AliasTableEntry> cachedAliasTable;
    AliasTableModel *parent;

    AliasTablePriv(CWallet *wallet, AliasTableModel *parent):
        wallet(wallet), parent(parent) {}

    void refreshAliasTable(AliasModelType type)
    {

        cachedAliasTable.clear();
        {
			string strMethod = string("aliaslist");
			UniValue params(UniValue::VARR); 
			UniValue result;
			string name_str;
			string value_str;
			string privvalue_str;
			string expires_in_str;
			string expires_on_str;
			string expired_str;
			int expired = 0;
			int buyer_rating = 0;
			int buyer_ratingcount = 0;
			int seller_rating = 0;
			int seller_ratingcount = 0;
			int arbiter_rating = 0;
			int arbiter_ratingcount = 0;
			string safesearch_str;
			int expires_in = 0;
			int expires_on = 0;
			
			int lastupdate_height = 0;
			try {
				result = tableRPC.execute(strMethod, params);
				if (result.type() == UniValue::VARR)
				{
					name_str = "";
					value_str = "";
					privvalue_str = "";
					expires_in_str = "";
					expires_on_str = "";
					safesearch_str = "";
					expired = 0;
					expires_in = 0;
					expires_on = 0;
					lastupdate_height = 0;
					buyer_rating = 0;
					buyer_ratingcount = 0;
					seller_rating = 0;
					seller_ratingcount = 0;
					arbiter_rating = 0;
					arbiter_ratingcount = 0;
			
					const UniValue &arr = result.get_array();
				    for (unsigned int idx = 0; idx < arr.size(); idx++) {
					    const UniValue& input = arr[idx];
						if (input.type() != UniValue::VOBJ)
							continue;
						const UniValue& o = input.get_obj();
						name_str = "";
						value_str = "";
						privvalue_str = "";
						expires_in_str = "";
						expires_on_str = "";
						safesearch_str = "";
						expired = 0;
						buyer_rating = 0;
						buyer_ratingcount = 0;
						seller_rating = 0;
						seller_ratingcount = 0;
						arbiter_rating = 0;
						arbiter_ratingcount = 0;
						expires_in = 0;
						expires_on = 0;
						lastupdate_height = 0;
				
						const UniValue& name_value = find_value(o, "name");
						if (name_value.type() == UniValue::VSTR)
							name_str = name_value.get_str();
						const UniValue& value_value = find_value(o, "value");
						if (value_value.type() == UniValue::VSTR)
							value_str = value_value.get_str();
						const UniValue& privvalue_value = find_value(o, "privatevalue");
						if (privvalue_value.type() == UniValue::VSTR)
							privvalue_str = privvalue_value.get_str();
						const UniValue& expires_on_value = find_value(o, "expires_on");
						if (expires_on_value.type() == UniValue::VNUM)
							expires_on = expires_on_value.get_int();
						const UniValue& expires_in_value = find_value(o, "expires_in");
						if (expires_in_value.type() == UniValue::VNUM)
							expires_in = expires_in_value.get_int();
						const UniValue& expired_value = find_value(o, "expired");
						if (expired_value.type() == UniValue::VNUM)
							expired = expired_value.get_int();
						const UniValue& buyer_rating_value = find_value(o, "buyer_rating");
						if (buyer_rating_value.type() == UniValue::VNUM)
							buyer_rating = buyer_rating_value.get_int();
						const UniValue& seller_rating_value = find_value(o, "seller_rating");
						if (seller_rating_value.type() == UniValue::VNUM)
							seller_rating = seller_rating_value.get_int();
						const UniValue& arbiter_rating_value = find_value(o, "arbiter_rating");
						if (arbiter_rating_value.type() == UniValue::VNUM)
							arbiter_rating = arbiter_rating_value.get_int();
						const UniValue& buyer_ratingcount_value = find_value(o, "buyer_ratingcount");
						if (buyer_ratingcount_value.type() == UniValue::VNUM)
							buyer_ratingcount = buyer_ratingcount_value.get_int();
						const UniValue& seller_ratingcount_value = find_value(o, "seller_ratingcount");
						if (seller_ratingcount_value.type() == UniValue::VNUM)
							seller_ratingcount = seller_ratingcount_value.get_int();
						const UniValue& arbiter_ratingcount_value = find_value(o, "arbiter_ratingcount");
						if (arbiter_ratingcount_value.type() == UniValue::VNUM)
							arbiter_ratingcount = arbiter_ratingcount_value.get_int();
						const UniValue& safesearch_value = find_value(o, "safesearch");
						if (safesearch_value.type() == UniValue::VSTR)
							safesearch_str = safesearch_value.get_str();
						const UniValue& pending_value = find_value(o, "pending");
						int pending = 0;
						if (pending_value.type() == UniValue::VNUM)
							pending = pending_value.get_int();

						if(expired == 1)
						{
							expired_str = "Expired";
						}
						else if(pending == 1)
						{
							expired_str = "Pending";
						}
						else
						{
							expired_str = "Valid";
						}

						
						expires_in_str = strprintf("%d Blocks", expires_in);
						expires_on_str = strprintf("Block %d", expires_on);
	
						updateEntry(QString::fromStdString(name_str), QString::fromStdString(value_str), QString::fromStdString(privvalue_str), QString::fromStdString(expires_on_str), QString::fromStdString(expires_in_str), QString::fromStdString(expired_str), QString::fromStdString(safesearch_str),buyer_rating,buyer_ratingcount, seller_rating,seller_ratingcount, arbiter_rating,arbiter_ratingcount, type, CT_NEW); 
					}
				}
 			}
			catch (UniValue& objError)
			{
				return;
			}
			catch(std::exception& e)
			{
				return;
			}           
         }

    }

    void updateEntry(const QString &alias, const QString &value, const QString &privvalue, const QString &expires_on,const QString &expires_in, const QString &expired, const QString &safesearch, int buyer_rating, int buyer_ratingcount, int seller_rating, int seller_ratingcount, int arbiter_rating, int arbiter_ratingcount,AliasModelType type, int status)
    {
		if(!parent || parent->modelType != type)
		{
			return;
		}
        // Find alias / value in model
        QList<AliasTableEntry>::iterator lower = qLowerBound(
            cachedAliasTable.begin(), cachedAliasTable.end(), alias, AliasTableEntryLessThan());
        QList<AliasTableEntry>::iterator upper = qUpperBound(
            cachedAliasTable.begin(), cachedAliasTable.end(), alias, AliasTableEntryLessThan());
        int lowerIndex = (lower - cachedAliasTable.begin());
        int upperIndex = (upper - cachedAliasTable.begin());
        bool inModel = (lower != upper);
		int index;
        AliasTableEntry::Type newEntryType = AliasTableEntry::Alias;

        switch(status)
        {
        case CT_NEW:
			index = parent->lookupAlias(alias);
            if(inModel || index != -1)
            {
                break;
            
            }
            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            cachedAliasTable.insert(lowerIndex, AliasTableEntry(newEntryType, alias, value, privvalue, expires_on, expires_in, expired, safesearch, buyer_rating, buyer_ratingcount, seller_rating, seller_ratingcount, arbiter_rating, arbiter_ratingcount));
            parent->endInsertRows();
            break;
        case CT_UPDATED:
            if(!inModel)
            {
                break;
            }
            lower->type = newEntryType;
            lower->value = value;
			lower->privvalue = privvalue;
			lower->expires_on = expires_on;
			lower->expires_in = expires_in;
			lower->expired = expired;
			lower->safesearch = safesearch;
			lower->buyer_rating = buyer_rating;
			lower->buyer_ratingcount = buyer_ratingcount;
			lower->seller_rating = seller_rating;
			lower->seller_ratingcount = seller_ratingcount;
			lower->arbiter_rating = arbiter_rating;
			lower->arbiter_ratingcount = arbiter_ratingcount;
            parent->emitDataChanged(lowerIndex);
            break;
        case CT_DELETED:
            if(!inModel)
            {
                break;
            }
            parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex-1);
            cachedAliasTable.erase(lower, upper);
            parent->endRemoveRows();
            break;
        }
    }

    int size()
    {
        return cachedAliasTable.size();
    }

    AliasTableEntry *index(int idx)
    {
        if(idx >= 0 && idx < cachedAliasTable.size())
        {
            return &cachedAliasTable[idx];
        }
        else
        {
            return 0;
        }
    }
};

AliasTableModel::AliasTableModel(CWallet *wallet, WalletModel *parent,  AliasModelType type) :
    QAbstractTableModel(parent),walletModel(parent),wallet(wallet),priv(0), modelType(type)
{

	columns << tr("Alias") << tr("Expires On") << tr("Expires In") << tr("Alias Status") << tr("Buyer Rating") << tr("Seller Rating") << tr("Arbiter Rating");		 
    priv = new AliasTablePriv(wallet, this);
	refreshAliasTable();
}

AliasTableModel::~AliasTableModel()
{
    delete priv;
}
void AliasTableModel::refreshAliasTable() 
{
	if(modelType != MyAlias)
		return;
	clear();
	priv->refreshAliasTable(modelType);
}
int AliasTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int AliasTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant AliasTableModel::data(const QModelIndex &index, int role) const
{
	QString ratingStr;
    if(!index.isValid())
        return QVariant();

    AliasTableEntry *rec = static_cast<AliasTableEntry*>(index.internalPointer());

    if(role == Qt::DisplayRole || role == Qt::EditRole)
    {
        switch(index.column())
        {
        case Value:
            return rec->value;
        case PrivValue:
            return rec->privvalue;
        case Name:
            return rec->alias;
        case ExpiresOn:
            return rec->expires_on;
        case ExpiresIn:
            return rec->expires_in;
        case Expired:
            return rec->expired;
        case SafeSearch:
            return rec->safesearch;
        case RatingAsBuyer:
			
			if(rec->buyer_ratingcount == 1)
				ratingStr = tr("Rating");
			else
				ratingStr = tr("Ratings");
			return QString::number(rec->buyer_rating) + " " + tr("Stars") + "(" + QString::number(rec->buyer_ratingcount) + " " +  ratingStr + ")";
        case RatingAsSeller:
			
			if(rec->seller_ratingcount == 1)
				ratingStr = tr("Rating");
			else
				ratingStr = tr("Ratings");
			return QString::number(rec->seller_rating) + " " + tr("Stars") + "(" + QString::number(rec->seller_ratingcount) + " " + ratingStr + ")";
        case RatingAsArbiter:
			
			if(rec->arbiter_ratingcount == 1)
				ratingStr = tr("Rating");
			else
				ratingStr = tr("Ratings");
			return QString::number(rec->arbiter_rating) + " " + tr("Stars") + "(" + QString::number(rec->arbiter_ratingcount) + " " + ratingStr + ")";
        }
    }
    else if (role == TypeRole)
    {
        switch(rec->type)
        {
        case AliasTableEntry::Alias:
            return Alias;
        default: break;
        }
    }
    else if (role == NameRole)
    {
         return rec->alias;
    }
    else if (role == ExpiredRole)
    {
        return rec->expired;
    }
    else if (role == SafeSearchRole)
    {
         return rec->safesearch;
    }
    return QVariant();
}

bool AliasTableModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if(!index.isValid())
        return false;
    AliasTableEntry *rec = static_cast<AliasTableEntry*>(index.internalPointer());

    editStatus = OK;

    if(role == Qt::EditRole)
    {
        switch(index.column())
        {
        case RatingAsBuyer:
            // Do nothing, if old value == new value
            if(rec->buyer_rating == value.toInt())
            {
                editStatus = NO_CHANGES;
                return false;
            }
			break;              
         case RatingAsSeller:
            // Do nothing, if old value == new value
            if(rec->seller_rating == value.toInt())
            {
                editStatus = NO_CHANGES;
                return false;
            }
			break;
        case RatingAsArbiter:
            // Do nothing, if old value == new value
            if(rec->arbiter_rating == value.toInt())
            {
                editStatus = NO_CHANGES;
                return false;
            }
			break;
        case ExpiresOn:
            // Do nothing, if old value == new value
            if(rec->expires_on == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
                     
            break;
        case ExpiresIn:
            // Do nothing, if old value == new value
            if(rec->expires_in == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
           
            break;
        case Expired:
            // Do nothing, if old value == new value
            if(rec->expired == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
           
            break;
        case Value:
            // Do nothing, if old value == new value
            if(rec->value == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            break;
        case PrivValue:
            // Do nothing, if old value == new value
            if(rec->privvalue == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
        case Name:
            // Do nothing, if old alias == new alias
            if(rec->alias == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            // Check for duplicate aliases to prevent accidental deletion of aliases, if you try
            // to paste an existing alias over another alias (with a different label)
            else if(lookupAlias(rec->alias) != -1)
            {
                editStatus = DUPLICATE_ALIAS;
                return false;
            }
            // Double-check that we're not overwriting a receiving alias
            else if(rec->type == AliasTableEntry::Alias)
            {
                {
                    // update alias
                }
            }
            break;
        }
        return true;
    }
    return false;
}

QVariant AliasTableModel::headerData(int section, Qt::Orientation orientation, int role) const
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

Qt::ItemFlags AliasTableModel::flags(const QModelIndex &index) const
{
    if(!index.isValid())
        return 0;
    Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    return retval;
}

QModelIndex AliasTableModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    AliasTableEntry *data = priv->index(row);
    if(data)
    {
        return createIndex(row, column, priv->index(row));
    }
    else
    {
        return QModelIndex();
    }
}

void AliasTableModel::updateEntry(const QString &alias, const QString &value, const QString &privvalue, const QString &expires_on,const QString &expires_in, const QString &expired, const QString &safesearch, int buyer_rating, int buyer_ratingcount, int seller_rating, int seller_ratingcount,int arbiter_rating, int arbiter_ratingcount,AliasModelType type, int status)
{
    // Update alias book model from Syscoin core
    priv->updateEntry(alias, value, privvalue, expires_on, expires_in, expired, safesearch, buyer_rating, buyer_ratingcount, seller_rating, seller_ratingcount, arbiter_rating, arbiter_ratingcount, type, status);
}

QString AliasTableModel::addRow(const QString &type, const QString &alias, const QString &value, const QString &privvalue, const QString &expires_on,const QString &expires_in, const QString &expired, const QString &safesearch, int buyer_rating, int buyer_ratingcount, int seller_rating, int seller_ratingcount, int arbiter_rating, int arbiter_ratingcount)
{
    std::string strAlias = alias.toStdString();
    editStatus = OK;
    // Check for duplicate aliases
    {
        LOCK(wallet->cs_wallet);
        if(lookupAlias(alias) != -1)
        {
            editStatus = DUPLICATE_ALIAS;
            return QString();
        }
    }

    // Add entry

    return QString::fromStdString(strAlias);
}
void AliasTableModel::clear()
{
	beginResetModel();
    priv->cachedAliasTable.clear();
	endResetModel();
}


int AliasTableModel::lookupAlias(const QString &alias) const
{
    QModelIndexList lst = match(index(0, Name, QModelIndex()),
                                Qt::EditRole, alias, 1, Qt::MatchExactly);
    if(lst.isEmpty())
    {
        return -1;
    }
    else
    {
        return lst.at(0).row();
    }
}

void AliasTableModel::emitDataChanged(int idx)
{
    Q_EMIT dataChanged(index(idx, 0, QModelIndex()), index(idx, columns.length()-1, QModelIndex()));
}

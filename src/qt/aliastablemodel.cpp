
#include "aliastablemodel.h"

#include "guiutil.h"
#include "walletmodel.h"

#include "wallet.h"
#include "base58.h"

#include <QFont>

using namespace std;
using namespace json_spirit;
bool GetValueOfAliasTxHash(const uint256 &txHash, vector<unsigned char>& vchValue, uint256& hash, int& nHeight);

const QString AliasTableModel::Alias = "A";
const QString AliasTableModel::DataAlias = "D";


extern const CRPCTable tableRPC;
struct AliasTableEntry
{
    enum Type {
        Alias,
        DataAlias
    };

    Type type;
    QString value;
    QString alias;
	QString lastupdate_height;
	QString expires_on;
	QString expires_in;
	QString expired;
    AliasTableEntry() {}
    AliasTableEntry(Type type, const QString &alias, const QString &value, const QString &lastupdate_height, const QString &expires_on,const QString &expires_in, const QString &expired):
        type(type), alias(alias), value(value), lastupdate_height(lastupdate_height), expires_on(expires_on), expires_in(expires_in), expired(expired) {}
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

#define NAMEMAPTYPE map<vector<unsigned char>, uint256>

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
	        Array params; 
			Value result ;
			string name_str;
			string value_str;
			string expires_in_str;
			string lastupdate_height_str;
			string expires_on_str;
			string expired_str;
			int expired = 0;
			int expires_in = 0;
			int expires_on = 0;
			
			int lastupdate_height = 0;
			try {
				result = tableRPC.execute(strMethod, params);
			}
			catch (Object& objError)
			{
				return;
			}
			catch(std::exception& e)
			{
				return;
			}
			if (result.type() == array_type)
			{
				name_str = "";
				value_str = "";
				expires_in_str = "";
				lastupdate_height_str = "";
				expires_on_str = "";

				expired = 0;
				expires_in = 0;
				expires_on = 0;
				lastupdate_height = 0;
		
				Array arr = result.get_array();
				BOOST_FOREACH(Value& input, arr)
				{
					if (input.type() != obj_type)
						continue;
					Object& o = input.get_obj();
					name_str = "";
					value_str = "";
					expires_in_str = "";
					lastupdate_height_str = "";
					expires_on_str = "";
					expired = 0;
					expires_in = 0;
					expires_on = 0;
					lastupdate_height = 0;
			
					const Value& name_value = find_value(o, "name");
					if (name_value.type() == str_type)
						name_str = name_value.get_str();
					const Value& value_value = find_value(o, "value");
					if (value_value.type() == str_type)
						value_str = value_value.get_str();
					const Value& lastupdate_height_value = find_value(o, "lastupdate_height");
					if (lastupdate_height_value.type() == int_type)
						lastupdate_height = lastupdate_height_value.get_int();
					const Value& expires_on_value = find_value(o, "expires_on");
					if (expires_on_value.type() == int_type)
						expires_on = expires_on_value.get_int();
					const Value& expires_in_value = find_value(o, "expires_in");
					if (expires_in_value.type() == int_type)
						expires_in = expires_in_value.get_int();
					const Value& expired_value = find_value(o, "expired");
					if (expired_value.type() == int_type)
						expired = expired_value.get_int();
					if(expired == 1)
					{
						expired_str = "Expired";
					}
					else
					{
						expired_str = "Valid";
					}
					expires_in_str = strprintf("%d Blocks", expires_in);
					expires_on_str = strprintf("Block %d", expires_on);
					if(lastupdate_height > 0)
						lastupdate_height_str = strprintf("Block %d", lastupdate_height);
					
					updateEntry(QString::fromStdString(name_str), QString::fromStdString(value_str), QString::fromStdString(lastupdate_height_str), QString::fromStdString(expires_on_str), QString::fromStdString(expires_in_str), QString::fromStdString(expired_str),type, CT_NEW); 
				}
			}
            
         }
        // qLowerBound() and qUpperBound() require our cachedAliasTable list to be sorted in asc order
        qSort(cachedAliasTable.begin(), cachedAliasTable.end(), AliasTableEntryLessThan());
    }

    void updateEntry(const QString &alias, const QString &value, const QString &lastupdate_height, const QString &expires_on,const QString &expires_in, const QString &expired, AliasModelType type, int status)
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
        AliasTableEntry::Type newEntryType = /*isData ? AliasTableEntry::DataAlias :*/ AliasTableEntry::Alias;

        switch(status)
        {
        case CT_NEW:
			index = parent->lookupAlias(alias);
            if(inModel || index != -1)
            {
                OutputDebugStringF("Warning: AliasTablePriv::updateEntry: Got CT_NOW, but entry is already in model\n");
                break;
            
            }
            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            cachedAliasTable.insert(lowerIndex, AliasTableEntry(newEntryType, alias, value, lastupdate_height, expires_on, expires_in, expired));
            parent->endInsertRows();
            break;
        case CT_UPDATED:
            if(!inModel)
            {
                OutputDebugStringF("Warning: AliasTablePriv::updateEntry: Got CT_UPDATED, but entry is not in model\n");
                break;
            }
            lower->type = newEntryType;
            lower->value = value;
			lower->lastupdate_height = lastupdate_height;
			lower->expires_on = expires_on;
			lower->expires_in = expires_in;
			lower->expired = expired;
            parent->emitDataChanged(lowerIndex);
            break;
        case CT_DELETED:
            if(!inModel)
            {
                OutputDebugStringF("Warning: AliasTablePriv::updateEntry: Got CT_DELETED, but entry is not in model\n");
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

	columns << tr("Alias") << tr("Value") << tr("Last Update") << tr("Expires On") << tr("Expires In") << tr("Alias Status");		 
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
    if(!index.isValid())
        return QVariant();

    AliasTableEntry *rec = static_cast<AliasTableEntry*>(index.internalPointer());

    if(role == Qt::DisplayRole || role == Qt::EditRole)
    {
        switch(index.column())
        {
        case Value:
            return rec->value;
        case Name:
            return rec->alias;
        case LastUpdateHeight:
            return rec->lastupdate_height;
        case ExpiresOn:
            return rec->expires_on;
        case ExpiresIn:
            return rec->expires_in;
        case Expired:
            return rec->expired;
        }
    }
    else if (role == Qt::FontRole)
    {
        QFont font;
        if(index.column() == Value)
        {
            font = GUIUtil::bitcoinAddressFont();
        }
        return font;
    }
    else if (role == TypeRole)
    {
        switch(rec->type)
        {
        case AliasTableEntry::Alias:
            return Alias;
        case AliasTableEntry::DataAlias:
            return DataAlias;
        default: break;
        }
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
        case LastUpdateHeight:
            // Do nothing, if old value == new value
            if(rec->lastupdate_height == value.toString())
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
            //wallet->SetAddressBookName(CBitcoinAlias(rec->alias.toStdString()).Get(), value.toString().toStdString());
            break;
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

void AliasTableModel::updateEntry(const QString &alias, const QString &value, const QString &lastupdate_height, const QString &expires_on,const QString &expires_in, const QString &expired, AliasModelType type, int status)
{
    // Update alias book model from Syscoin core
    priv->updateEntry(alias, value, lastupdate_height, expires_on, expires_in, expired, type, status);
}

QString AliasTableModel::addRow(const QString &type, const QString &alias, const QString &value, const QString &lastupdate_height, const QString &expires_on,const QString &expires_in, const QString &expired)
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

/* Look up value for alias, if not found return empty string.
 */
QString AliasTableModel::valueForAlias(const QString &alias) const
{
	CBitcoinAddress address_parsed(alias.toStdString());
	if(address_parsed.IsValid() && address_parsed.isAlias)
		return QString::fromStdString(address_parsed.ToString());
    return QString::fromStdString("{}");
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
    emit dataChanged(index(idx, 0, QModelIndex()), index(idx, columns.length()-1, QModelIndex()));
}

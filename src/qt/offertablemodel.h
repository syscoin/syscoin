#ifndef OFFERTABLEMODEL_H
#define OFFERTABLEMODEL_H

#include <QAbstractTableModel>
#include <QStringList>

class OfferTablePriv;
class CWallet;
class WalletModel;

enum OfferType {AllOffers=0,MyOffers};

typedef enum OfferType OfferModelType;
/**
   Qt model of the offer                                                                                                                                                        book in the core. This allows views to access and modify the offer book.
 */
class OfferTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
	explicit OfferTableModel(CWallet *wallet, WalletModel *parent = 0, OfferModelType type = AllOffers);
    ~OfferTableModel();

    enum ColumnIndex {
        Name = 0,   /**< offer name */
        Category = 1,
        Title = 2,  /**< Offer value */
        Price = 3,
        Quantity = 4,
        ExpirationDepth = 5,
		Description = 6
    };

    enum RoleIndex {
        TypeRole = Qt::UserRole /**< Type of offer (#Send or #Receive) */
    };

    /** Return status of edit/insert operation */
    enum EditStatus {
        OK,                     /**< Everything ok */
        NO_CHANGES,             /**< No changes were made during edit operation */
        INVALID_OFFER,        /**< Unparseable offer */
        DUPLICATE_OFFER,      /**< Offer already in offer book */
        WALLET_UNLOCK_FAILURE  /**< Wallet could not be unlocked */
    };

    static const QString Offer;      /**< Specifies send offer */
    static const QString OfferAccept;   /**< Specifies offeraccept */

    /** @name Methods overridden from QAbstractTableModel
        @{*/
    int rowCount(const QModelIndex &parent) const;
    int columnCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    bool setData(const QModelIndex &index, const QVariant &value, int role);
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
    QModelIndex index(int row, int column, const QModelIndex &parent) const;
    bool removeRows(int row, int count, const QModelIndex &parent = QModelIndex());
    Qt::ItemFlags flags(const QModelIndex &index) const;
    /*@}*/

    /* Add an offer to the model.
       Returns the added offer on success, and an empty string otherwise.
     */
    QString addRow(const QString &type, const QString &title, const QString &offer, const QString &category, const QString &price,
                   const QString &quantity, const QString &expdepth, const QString &description);

    /* Look up label for offer in offer book, if not found return empty string.
     */
    QString valueForOffer(const QString &offer) const;

    /* Look up row index of an offer in the model.
       Return -1 if not found.
     */
    int lookupOffer(const QString &offer) const;

    EditStatus getEditStatus() const { return editStatus; }

private:
    WalletModel *walletModel;
    CWallet *wallet;
    OfferTablePriv *priv;
    QStringList columns;
    EditStatus editStatus;
	OfferModelType modelType;
    /** Notify listeners that data changed. */
    void emitDataChanged(int index);

public slots:
    /* Update offer list from core.
     */
    void updateEntry(const QString &offer, const QString &title, const QString &category, const QString &price,
		const QString &quantity, const QString &expdepth, const QString &description, OfferModelType type, int status);

    friend class OfferTablePriv;
};

#endif // OFFERTABLEMODEL_H

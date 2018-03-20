#ifndef CERTTABLEMODEL_H
#define CERTTABLEMODEL_H

#include <QAbstractTableModel>
#include <QStringList>

class CertIssuerTablePriv;
class CWallet;
class WalletModel;


class CertIssuerTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit CertIssuerTableModel(CWallet *wallet, WalletModel *parent = 0);
    ~CertIssuerTableModel();

    enum ColumnIndex {
        Name = 0,   /**< cert name */
        Title = 1,  /**< CertIssuer value */
        ExpirationDepth = 2
    };

    enum RoleIndex {
        TypeRole = Qt::UserRole /**< Type of cert (#Send or #Receive) */
    };

    /** Return status of edit/insert operation */
    enum EditStatus {
        OK,                     /**< Everything ok */
        NO_CHANGES,             /**< No changes were made during edit operation */
        INVALID_CERT,        /**< Unparseable cert */
        DUPLICATE_CERT,      /**< CertIssuer already in cert book */
        WALLET_UNLOCK_FAILURE  /**< Wallet could not be unlocked */
    };

    static const QString CertIssuer;      /**< Specifies certificate issuer */
    static const QString CertItem;   /**< Specifies certificate */

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

    /* Add an cert to the model.
       Returns the added cert on success, and an empty string otherwise.
     */
    QString addRow(const QString &type, const QString &title, const QString &cert, const QString &expdepth);

    /* Look up label for cert in cert book, if not found return empty string.
     */
    QString valueForCertIssuer(const QString &cert) const;

    /* Look up row index of an cert in the model.
       Return -1 if not found.
     */
    int lookupCertIssuer(const QString &cert) const;

    EditStatus getEditStatus() const { return editStatus; }

private:
    WalletModel *walletModel;
    CWallet *wallet;
    CertIssuerTablePriv *priv;
    QStringList columns;
    EditStatus editStatus;

    /** Notify listeners that data changed. */
    void emitDataChanged(int index);

public slots:
    /* Update cert list from core.
     */
    void updateEntry(const QString &cert, const QString &title, const QString &expdepth, bool isCertItem, int status);

    friend class CertIssuerTablePriv;
};

#endif // CERTTABLEMODEL_H

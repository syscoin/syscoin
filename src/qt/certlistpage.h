#ifndef CERTLISTPAGE_H
#define CERTLISTPAGE_H

#include <QDialog>

namespace Ui {
    class CertIssuerListPage;
}
class CertIssuerTableModel;
class OptionsModel;

QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QSortFilterProxyModel;
class QMenu;
class QModelIndex;
QT_END_NAMESPACE

/** Widget that shows a list of owned certes.
  */
class CertIssuerListPage : public QDialog
{
    Q_OBJECT

public:
    enum Tabs {
        CertIssuerTab = 0,
        CertItemTab = 1
    };

    enum Mode {
        ForTransferring, /**< Open cert book to pick cert for transferring */
        ForEditing  /**< Open cert book for editing */
    };

    explicit CertIssuerListPage(Mode mode, Tabs tab, QWidget *parent = 0);
    ~CertIssuerListPage();

    void setModel(CertIssuerTableModel *model);
    void setOptionsModel(OptionsModel *optionsModel);
    const QString &getReturnValue() const { return returnValue; }

public slots:
    void done(int retval);

private:
    Ui::CertIssuerListPage *ui;
    CertIssuerTableModel *model;
    OptionsModel *optionsModel;
    Mode mode;
    Tabs tab;
    QString returnValue;
    QSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QAction *deleteAction; // to be able to explicitly disable it
    QString newCertIssuerToSelect;

private slots:
    /** Create a new cert for receiving coins and / or add a new cert book entry */
    void on_newCertIssuer_clicked();
    /** Copy cert of currently selected cert entry to clipboard */
    void on_copyCertIssuer_clicked();

    /** Copy value of currently selected cert entry to clipboard (no button) */
    void onCopyCertIssuerValueAction();
    /** Edit currently selected cert entry (no button) */
    void onEditAction();
    /** Export button clicked */
    void on_exportButton_clicked();
    /** transfer the cert to a syscoin address  */
    void onTransferCertIssuerAction();

    /** Set button states based on selected tab and selection */
    void selectionChanged();
    /** Spawn contextual menu (right mouse menu) for cert book entry */
    void contextualMenu(const QPoint &point);
    /** New entry/entries were added to cert table */
    void selectNewCertIssuer(const QModelIndex &parent, int begin, int /*end*/);

signals:
    void transferCertIssuer(QString addr);
};

#endif // CERTLISTPAGE_H

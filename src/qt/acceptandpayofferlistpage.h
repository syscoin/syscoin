#ifndef ACCEPTANDPAYOFFERLISTPAGE_H
#define ACCEPTANDPAYOFFERLISTPAGE_H

#include <QDialog>

namespace Ui {
    class AcceptandPayOfferListPage;
}
class JSONRequest;
class OfferTableModel;
class OptionsModel;
class COffer;
QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QSortFilterProxyModel;
class QMenu;
class QModelIndex;
class QUrl;
QT_END_NAMESPACE

/** Widget that shows a list of owned offeres.
  */
class AcceptandPayOfferListPage : public QDialog
{
    Q_OBJECT

public:


    explicit AcceptandPayOfferListPage(QWidget *parent = 0);
    ~AcceptandPayOfferListPage();

    const QString &getReturnValue() const { return returnValue; }
	bool handleURI(const QUrl &uri, COffer* offerOut);
	bool handleURI(const QString& strURI, COffer* offerOut);
	void setValue(const COffer &offer);
public slots:
    void acceptandpay();

private:
    Ui::AcceptandPayOfferListPage *ui;
    QString returnValue;

    QMenu *contextMenu;
    QAction *deleteAction; // to be able to explicitly disable it


};

#endif // ACCEPTANDPAYOFFERLISTPAGE_H

#ifndef ESCROWCIPHERTOOL_H
#define ESCROWCIPHERTOOL_H
#include <QDialog>
class PlatformStyle;
class QDataWidgetMapper;
namespace Ui {
    class EscrowCipherTool;
}
QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE
/** Dialog for editing an address and associated information.
 */
class EscrowCipherTool : public QDialog
{
    Q_OBJECT

public:
    explicit EscrowCipherTool(const PlatformStyle *platformStyle, const QModelIndex &idx, QWidget *parent=0);
    ~EscrowCipherTool();
private:
	bool lookup();
private Q_SLOTS:
	void textChangedSlot();
	void on_okButton_clicked();
private:
	QDataWidgetMapper *mapper;
    Ui::EscrowCipherTool *ui;
	QString GUID;
};

#endif // ESCROWCIPHERTOOL_H
